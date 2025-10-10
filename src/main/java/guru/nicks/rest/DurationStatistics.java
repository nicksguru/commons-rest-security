package guru.nicks.rest;

import guru.nicks.utils.TextUtils;
import guru.nicks.utils.TimeUtils;

import am.ik.yavi.meta.ConstraintArguments;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.concurrent.atomic.LongAccumulator;

import static guru.nicks.validation.dsl.ValiDsl.check;

/**
 * Accumulates the total number of calls and execution time in a lock-free thread-safe manner. Under high concurrency,
 * the updates may be deferred, i.e. {@link #accumulateMillis(String, long)} may report outdated values.
 */
@RequiredArgsConstructor
@Slf4j
public class DurationStatistics {

    /**
     * Keys are request URIs.
     */
    private final Cache<String, DurationAccumulator> cache;

    private final String ttlAsWords;

    /**
     * To resist DoS attacks and a big number of legitimate {@code GET /something/ID} request URIs, the number of
     * request URIs whose statistics is retained (in RAM) and the retention period are limited. Storing more entries
     * means evicting old (presumably least frequently * used) ones.
     *
     * @param maxKeys         the maximum number of, for example, unique request URIs to retain in RAM
     * @param retentionPeriod time period for keeping the statistics in RAM
     */
    @ConstraintArguments
    public DurationStatistics(int maxKeys, Duration retentionPeriod) {
        check(maxKeys, _DurationStatisticsArgumentsMeta.MAXKEYS.name())
                .positiveOrZero();
        check(retentionPeriod, _DurationStatisticsArgumentsMeta.RETENTIONPERIOD.name())
                .constraint(Duration::isPositive, "must be positive");

        cache = Caffeine.newBuilder()
                .maximumSize(maxKeys)
                .expireAfterWrite(retentionPeriod)
                .build();

        ttlAsWords = TimeUtils.humanFormatDuration(retentionPeriod);
    }

    /**
     * Updates statistics for the given request URI.
     *
     * @param key    for example, a request URI ({@code null} is treated as an empty string)
     * @param millis milliseconds to add to the accumulator (ignored if negative)
     * @return statistics in a readable form with updated (or not - see class comment for details) values, or '' if no
     *         statistics are available at the moment
     */
    public String accumulateMillis(@Nullable String key, long millis) {
        // strictly speaking, blank values must be checked too, but it takes more time and it's not worth it
        if (key == null) {
            key = "";
        }

        DurationAccumulator accumulator = cache.get(key, theKey -> new DurationAccumulator());
        double averageMillis = accumulator.accumulateMillis(millis);

        // nothing to format because no data accumulated (despite the increment above; accumulation is asynchronous)
        if (averageMillis < 0) {
            return "";
        }

        // use StringBuilder with pre-allocated capacity instead of String.format for better performance under high load
        // (max. capacity: max. long (19) + fixed text (30) + magnitude text (30) + ttlAsWords length)
        return new StringBuilder(80)
                .append(Math.round(averageMillis))
                .append("ms average after ")
                .append(TextUtils.getMagnitudeOfCount(accumulator.getTotalCalls()))
                .append(" calls during past ")
                .append(ttlAsWords)
                .toString();
    }

    /**
     * Accumulates the total number of calls and the total time spent in a lock-free thread-safe manner. For further
     * information, see {@link #accumulateMillis(long)}.
     */
    @RequiredArgsConstructor
    public static class DurationAccumulator {

        /**
         * Number of calls. The only way to update and read it is {@link #accumulateMillis(long)}. Should NOT be treated
         * as an exact value because the underlying framework defers updates under a high concurrent load. See also edge
         * cases described in {@link #accumulateWithLongLimit(long, long)}.
         */
        private final LongAccumulator totalCalls = new LongAccumulator(this::accumulateWithLongLimit, 0);

        /**
         * Total time spent. The only way to update and read it is {@link #accumulateMillis(long)}. Should NOT be
         * treated as an exact value because the underlying framework defers updates under a high concurrent load.  See
         * also edge cases described in {@link #accumulateWithLongLimit(long, long)}.
         */
        private final LongAccumulator totalMillis = new LongAccumulator(this::accumulateWithLongLimit, 0);

        /**
         * Returns the total number of calls accumulated. Should NOT be treated as an exact value because the underlying
         * framework defers updates under a high concurrent load.
         *
         * @return the accumulated number of calls
         */
        public long getTotalCalls() {
            return totalCalls.get();
        }

        /**
         * Returns the total time accumulated. Should NOT be treated as an exact value because the underlying framework
         * defers updates under a high concurrent load.
         *
         * @return the accumulated time in milliseconds
         */
        public long getTotalMillis() {
            return totalMillis.get();
        }

        /**
         * Calculates the average execution time per call based on the accumulated total time and total number of
         * calls.
         * <p>
         * WARNING: the returned value should NOT be treated as exact because the underlying framework may defer updates
         * under high concurrent load, which can result in temporarily inconsistent values between total time and call
         * count.
         *
         * @return the average execution time in milliseconds per call, or -1 if no calls have been accumulated
         */
        public double getAverageMillis() {
            long calls = totalCalls.get();

            return (calls > 0)
                    ? (double) totalMillis.get() / calls
                    : -1;
        }

        /**
         * Adds to the total time spent AND increments the total number of calls in a lock-free thread-safe manner with
         * side effects adherent to {@link LongAccumulator}, namely: under a concurrent load the update may be
         * deferred.
         * <p>
         * If the new total would exceed {@link Long#MAX_VALUE}, it's fixed at {@link Long#MAX_VALUE} forever.
         *
         * @param millis milliseconds to add (ignored if negative)
         * @return the result of {@link #getAverageMillis()} with caveats described above
         */
        public double accumulateMillis(long millis) {
            if (millis >= 0) {
                totalCalls.accumulate(1L);
                totalMillis.accumulate(millis);
            }

            return getAverageMillis();
        }

        /**
         * Called by {@link LongAccumulator#accumulate(long)}. {@link LongAccumulator} description states:
         * <p>
         * <i>The supplied accumulator function should be side effect-free, since it may be re-applied when
         * attempted updates fail due to contention among threads.</i>
         * <p>
         * If the new total would exceed {@link Long#MAX_VALUE} after adding {@code valueToAdd}, it's fixed at
         * {@link Long#MAX_VALUE} forever.
         *
         * @param currentTotal current accumulated value
         * @param valueToAdd   value to add (ignored if not positive)
         * @return new accumulated value
         */
        private long accumulateWithLongLimit(long currentTotal, long valueToAdd) {
            // ignore non-positive values
            if (valueToAdd <= 0) {
                return currentTotal;
            }

            // limit already reached
            if (currentTotal == Long.MAX_VALUE) {
                return Long.MAX_VALUE;
            }

            // make sure new total will not exceed max. long (if current total is negative, it will not: adding
            // max. long to a negative current total will actually subtract the current total from max. long)
            if (currentTotal <= 0) {
                return currentTotal + valueToAdd;
            }

            long maxDelta = Long.MAX_VALUE - currentTotal;

            if (valueToAdd > maxDelta) {
                return Long.MAX_VALUE;
            }

            return currentTotal + valueToAdd;
        }

    }

}
