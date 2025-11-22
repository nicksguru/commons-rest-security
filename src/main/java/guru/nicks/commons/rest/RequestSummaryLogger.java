package guru.nicks.commons.rest;

import guru.nicks.commons.log.domain.LogContext;
import guru.nicks.commons.security.filter.AbstractRequestSummaryFilter;
import guru.nicks.commons.security.filter.LogContextFilter;
import guru.nicks.commons.utils.DurationStatistics;
import guru.nicks.commons.utils.HttpRequestUtils;
import guru.nicks.commons.utils.JvmUtils;

import am.ik.yavi.meta.ConstraintArguments;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.collect.ImmutableRangeMap;
import com.google.common.collect.Range;
import com.google.common.collect.RangeMap;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.TriConsumer;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotNull;

/**
 * Here's what's stored in {@link MDC} by {@link #accept(String, HttpServletResponse, Duration)} (this method is
 * supposed to be called from {@link AbstractRequestSummaryFilter}):
 * <ul>
 *  <li>parameters described in {@link LogContextFilter#storeRequestParametersInMdc(HttpServletRequest)}</li>
 *  <li>request ID ({@link LogContext#TRACE_ID} is stored in MDC by Micrometer;
 *      {@value LogContext#RESPONSE_TRACE_ID_HEADER} response header borrows its value)</li>
 *  <li>free RAM available to JVM ({@link LogContext#RAM_FREE_MB})</li>
 *  <li>max. RAM available to JVM ({@link LogContext#RAM_MAX_MB})</li>
 *  <li>response HTTP status code (in MDC - {@link LogContext#RESPONSE_HTTP_STATUS})</li>
 *  <li>request processing duration in milliseconds (both in MDC - {@link LogContext#RESPONSE_MS_ELAPSED} and in
 *      response headers - {@value LogContext#RESPONSE_MS_ELAPSED_HEADER})</li>
 *  <li>average number of milliseconds ({@code long}, not {@code double}) request completion has taken for the current
 *      request URI; for accuracy caveats, see {@link DurationStatistics}</li>
 *  <li>number of times (the magnitude actually, such as 'hundreds of') the current request URI has been called; for
 *      accuracy caveats, see {@link DurationStatistics}</li>
 *  <li>a warning if request execution time has exceeded the 'slow threshold'</li>
 * </ul>
 */
@Slf4j
public class RequestSummaryLogger implements TriConsumer<String, HttpServletResponse, Duration> {

    private final DurationStatistics durationStatistics;

    /**
     * If {@code null}, then not applicable.
     */
    private final Duration slowThreshold;

    /**
     * Constructor.
     *
     * @param durationStatistics the accumulator used to collect and calculate request statistics; must not be null
     * @param slowThreshold      the duration threshold above which requests are considered slow; may be null to disable
     *                           slow request detection, or must be positive if provided
     */
    @ConstraintArguments
    public RequestSummaryLogger(DurationStatistics durationStatistics, @Nullable Duration slowThreshold) {
        this.durationStatistics = checkNotNull(durationStatistics,
                _RequestSummaryLoggerArgumentsMeta.DURATIONSTATISTICS.name());
        this.slowThreshold = Optional.ofNullable(slowThreshold)
                .filter(Duration::isPositive)
                .orElse(null);
    }

    @Override
    public void accept(String requestUri, HttpServletResponse response, Duration requestDuration) {
        long millisElapsed = requestDuration.toMillis();

        Tasks.setResponseHeaders(millisElapsed, response::setHeader);
        Tasks.setLogContext(millisElapsed, response.getStatus());

        boolean requestIsSlow = (slowThreshold != null) && (requestDuration.compareTo(slowThreshold) > 0);
        String millisAccumulated = durationStatistics.accumulateMillis(requestUri, millisElapsed);
        Tasks.logMessage(millisElapsed, millisAccumulated, requestIsSlow, response.getStatus());
    }

    @UtilityClass
    private static class Tasks {

        public void setResponseHeaders(long millisElapsed, BiConsumer<String, String> headerSetter) {
            LogContext.TRACE_ID
                    .find()
                    .ifPresent(traceId -> headerSetter.accept(LogContext.RESPONSE_TRACE_ID_HEADER, traceId));

            headerSetter.accept(LogContext.RESPONSE_MS_ELAPSED_HEADER, String.valueOf(millisElapsed));
        }

        public void setLogContext(long millisElapsed, int httpStatusCode) {
            // these values are cached for a while and may change at any moment (including the max. memory limit)
            LogContext.RAM_MAX_MB.put(JvmUtils.getMaxMemory().toMegabytes());
            LogContext.RAM_FREE_MB.put(JvmUtils.getFreeMemory().toMegabytes());

            LogContext.RESPONSE_MS_ELAPSED.put(millisElapsed);
            LogContext.RESPONSE_HTTP_STATUS.put(httpStatusCode);
        }

        public void logMessage(long millisElapsed, String millisAccumulated, boolean requestIsSlow,
                int httpStatusCode) {
            // log bare HTTP status code if it can't be resolved (some cloud providers have custom codes)
            String httpStatusOrCode = HttpRequestUtils.resolveHttpStatus(httpStatusCode)
                    .map(HttpStatus::toString)
                    .orElse(String.valueOf(httpStatusCode));

            // StringBuilder with pre-allocated capacity instead of String.format for better performance under high load
            StringBuilder messageBuilder = new StringBuilder(150);
            messageBuilder.append("Request finished with status [")
                    .append(httpStatusOrCode)
                    .append("], took ")
                    .append(millisElapsed)
                    .append("ms");

            if (requestIsSlow) {
                messageBuilder.append(" [SLOW]");
            }

            if (StringUtils.isNotBlank(millisAccumulated)) {
                messageBuilder.append(" (")
                        .append(millisAccumulated)
                        .append(")");
            }

            LoggerDetector
                    .detect(httpStatusCode, requestIsSlow)
                    .accept(messageBuilder.toString());
        }

    }

    @UtilityClass
    public static class LoggerDetector {

        public static final Consumer<String> DEFAULT_LOGGER = log::info;

        /**
         * Range map based on HTTP status code ranges and, on the nested key, on whether the request was slow (the
         * {@code true} key means it was). Provides {@code O(log n)} lookup performance.
         */
        private static final RangeMap<Integer, Map<Boolean, Consumer<String>>> LOGGER_BY_HTTP_STATUS =
                ImmutableRangeMap.<Integer, Map<Boolean, Consumer<String>>>builder()
                        // success codes (there are no standard codes below 100, but theoretically, any code may occur)
                        .put(Range.atMost(399), Map.of(
                                true, log::warn,
                                false, DEFAULT_LOGGER))

                        // 4xx client errors - no dependency on request slowness
                        .put(Range.closed(400, 499), Map.of(
                                true, log::warn,
                                false, log::warn))

                        // 5xx server errors - no dependency on request slowness
                        .put(Range.closed(500, 599), Map.of(
                                true, log::error,
                                false, log::error))

                        // there are no standard codes after 599, but theoretically, any code may occur
                        .put(Range.atLeast(600), Map.of(
                                true, log::warn,
                                false, DEFAULT_LOGGER))
                        .build();

        /**
         * Key format: (HTTP status * 10) + 1 if the request was slow, for example: 2000 for status 200 and non-slow
         * requests; 2001 for status 200 and slow requests. HTTP statuses are integers, therefore there's no numeric
         * overflow.
         * <p>
         * The maximum cache capacity must accommodate double the number of HTTP statuses to be stored.
         */
        private static final Cache<Long, Consumer<String>> LOGGER_CACHE = Caffeine.newBuilder()
                .maximumSize(100)
                .build();

        /**
         * Detects the appropriate logger (in parent class). Leverages caching which is impactful, as the HTTP status is
         * 200 most of the time.
         *
         * @param httpStatusCode HTTP status code
         * @param requestIsSlow  if the request was slow
         * @return the appropriate logger, or {@link #DEFAULT_LOGGER} if no condition applies
         */
        public static Consumer<String> detect(int httpStatusCode, boolean requestIsSlow) {
            long key = httpStatusCode * 10L + (requestIsSlow ? 1 : 0);

            // 'get' method may return null as per Caffeine specs, but never does in this particular case
            //noinspection DataFlowIssue
            return LOGGER_CACHE.get(key, theKey ->
                    Optional.ofNullable(LOGGER_BY_HTTP_STATUS.get(httpStatusCode))
                            .map(map -> map.get(requestIsSlow))
                            .orElse(DEFAULT_LOGGER));
        }

    }

}
