package guru.nicks.commons.auth.jwt;

import guru.nicks.commons.auth.domain.JwkInfo;
import guru.nicks.commons.cache.AsyncCacheRefresher;
import guru.nicks.commons.cache.CaffeineEntryExpirationCondition;
import guru.nicks.commons.utils.Resilience4jUtils;
import guru.nicks.commons.utils.json.JwkUtils;
import guru.nicks.commons.utils.text.TimeUtils;

import am.ik.yavi.meta.ConstraintArguments;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.github.resilience4j.decorators.Decorators;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.event.RetryOnErrorEvent;
import io.github.resilience4j.retry.event.RetryOnRetryEvent;
import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static guru.nicks.commons.validation.dsl.ValiDsl.check;
import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotNull;

/**
 * Does the same as {@link CompositeJwtDecoder}. Additionally, re-downloads JWKS preemptively and asynchronously (see
 * {@link CompositeJwtDecoder#atLeastOneKeyExpired()} and {@link #getAsyncRefreshTtlPercent()}) with retries.
 */
@Builder
@Slf4j
public class SelfRefreshingCompositeJwtDecoder implements JwtDecoder, AsyncCacheRefresher<CompositeJwtDecoder> {

    private static final String THE_ONLY_CACHE_KEY = "THE_ONLY_CACHE_KEY";

    private final Collection<? extends Supplier<JwkInfo>> jwkSuppliers;
    private final Collection<? extends Supplier<RSAPublicKey>> rsaSuppliers;
    private final Consumer<Throwable> alerter;

    /**
     * Not needed as a property (it's a temporary flag for constructor), just bound to Builder pattern.
     */
    private final boolean downloadJwkImmediately;

    @Getter // no 'onMethod_ = @Override', otherwise apidocs are not generated
    private final ScheduledExecutorService cacheRefresherTask = Executors.newSingleThreadScheduledExecutor();

    private final Retry jwkRetrier = Resilience4jUtils.createDefaultRetrier(getClass().getName() + " - JWK");
    private final Retry rsaRetrier = Resilience4jUtils.createDefaultRetrier(getClass().getName() + " - RSA");

    /**
     * Loads missing cache keys on demand.
     */
    private final LoadingCache<String, CompositeJwtDecoder> cache = CaffeineEntryExpirationCondition
            .createCaffeineBuilder(CompositeJwtDecoder::getExpirationDate)
            .maximumSize(1)
            .build(this::loadToCache);

    /**
     * Constructor.
     *
     * @param jwkSuppliers           JWKS supplier (presumably downloads keys from remote locations); can be called
     *                               periodically
     * @param rsaSuppliers           supplies public keys (such as parsed PEM files); can be called periodically
     * @param alerter                called when an exception occurs during JWK/RSA fetching/parsing
     * @param downloadJwkImmediately if {@code true}, JWK cache will be warmed up by the constructor, otherwise JWK will
     *                               be first downloaded when {@link #decode(String)} is called
     */
    @ConstraintArguments
    public SelfRefreshingCompositeJwtDecoder(
            Collection<? extends Supplier<JwkInfo>> jwkSuppliers,
            Collection<? extends Supplier<RSAPublicKey>> rsaSuppliers,
            Consumer<Throwable> alerter, boolean downloadJwkImmediately) {
        this.alerter = checkNotNull(alerter, _SelfRefreshingCompositeJwtDecoderArgumentsMeta.ALERTER.name());
        this.downloadJwkImmediately = downloadJwkImmediately;

        // Retry JWK fetching. No circuit breaker here because this is not a frequent operation and must always be
        // done on time (when the JWK key expires).
        this.jwkSuppliers = checkNotNull(
                jwkSuppliers, _SelfRefreshingCompositeJwtDecoderArgumentsMeta.JWKSUPPLIERS.name())
                .stream()
                .filter(Objects::nonNull)
                // apply retry to each supplier
                .map(Decorators::ofSupplier)
                .map(decorator -> decorator.withRetry(jwkRetrier))
                .map(Decorators.DecorateSupplier::decorate)
                //
                .toList();

        // retry RSA fetching
        this.rsaSuppliers = checkNotNull(
                rsaSuppliers, _SelfRefreshingCompositeJwtDecoderArgumentsMeta.RSASUPPLIERS.name())
                .stream()
                .filter(Objects::nonNull)
                // apply retry to each supplier
                .map(Decorators::ofSupplier)
                .map(decorator -> decorator.withRetry(rsaRetrier))
                .map(Decorators.DecorateSupplier::decorate)
                //
                .toList();

        jwkRetrier.getEventPublisher()
                .onRetry(this::handleJwkRetryEvent)
                .onError(this::handleJwkErrorEvent);

        rsaRetrier.getEventPublisher()
                .onRetry(this::handleRsaRetryEvent)
                .onError(this::handleRsaErrorEvent);

        if (downloadJwkImmediately) {
            refresh();
        }
    }

    /**
     * If at least one JWT signature has expired, reconstructs the whole keychain before decoding.
     *
     * @param token JWT as string
     * @return JWT as object
     */
    @Override
    public Jwt decode(String token) {
        return cache
                .get(THE_ONLY_CACHE_KEY)
                .decode(token);
    }

    @Override
    public CompletableFuture<CompositeJwtDecoder> createCacheRefreshFuture() {
        return cache.refresh(THE_ONLY_CACHE_KEY);
    }

    @Override
    public void possiblyScheduleAsyncRefresh(@Nullable Instant expirationDate) {
        calculateAsyncRefreshDate(expirationDate).ifPresent(asyncRefreshDate -> {
            Duration timeUntilAsyncRefresh = Duration.between(Instant.now(), asyncRefreshDate);

            log.info("All JWT public keys will be refreshed asynchronously in {} (at {})",
                    TimeUtils.humanFormatDuration(timeUntilAsyncRefresh), asyncRefreshDate);
            cacheRefresherTask.schedule(this::refresh, timeUntilAsyncRefresh.toMillis(), TimeUnit.MILLISECONDS);
        });
    }

    /**
     * Called by Caffeine internally. Re-downloads JWKS and PEMs. Sends an alert if all retries have failed for at least
     * one supplier.
     */
    @ConstraintArguments
    private CompositeJwtDecoder loadToCache(String key) {
        check(key, "cache key").constraint(THE_ONLY_CACHE_KEY::equals, "must equal '" + THE_ONLY_CACHE_KEY + "'");
        var jwkInfo = new ArrayList<JwkInfo>();

        // keys are provider IDs - each provider may have multiple keys
        var keyById = new HashMap<String, RSAPublicKey>();
        keyById.putAll(fetchKeysFromJwkSuppliers(jwkInfo));
        keyById.putAll(fetchKeysFomRsaSuppliers());

        Map<String, JwtDecoder> decoderById = createJwtDecoders(keyById);
        Instant chainExpirationDate = JwkUtils.findSmallestExpirationDate(jwkInfo).orElse(null);
        possiblyScheduleAsyncRefresh(chainExpirationDate);

        return new CompositeJwtDecoder(decoderById, chainExpirationDate);
    }

    /**
     * Fetches RSA keys from {@link #rsaSuppliers}.
     *
     * @return map of public keys: keyId -> key
     */
    private Map<String, RSAPublicKey> fetchKeysFomRsaSuppliers() {
        var i = new AtomicInteger();

        // name local decoders 'local-N' (N = 1, 2, ...)
        return rsaSuppliers.parallelStream()
                .map(Supplier::get)
                // create keys in the form: JWT-localN (N = 1, 2, ...)
                .collect(Collectors.toMap(key -> "JWT-" + "local" + i.incrementAndGet(), key -> key));
    }

    /**
     * Fetches JWKs from {@link #jwkSuppliers}.
     *
     * @param whereToStore where to store JWK info (needed for async refresh)
     * @return map of public keys: keyId -> key
     */
    private Map<String, RSAPublicKey> fetchKeysFromJwkSuppliers(Collection<? super JwkInfo> whereToStore) {
        List<JwkInfo> jwkInfo = jwkSuppliers.parallelStream()
                .map(Supplier::get)
                .toList();

        whereToStore.addAll(jwkInfo);
        var keys = new HashMap<String, RSAPublicKey>();

        // create decoder for each public key present in JWK and name it 'providerId-N' (N = 1, 2, ...)
        jwkInfo.forEach(jwk -> {
            List<RSAPublicKey> publicKeys = JwkUtils.extractPublicKeys(jwk);
            var i = new AtomicInteger();

            // create keys in the form: JWT-providerIdN (N = 1, 2, ...)
            publicKeys.forEach(key ->
                    keys.put("JWT-" + jwk.authProviderId() + i.incrementAndGet(), key));
        });

        return keys;
    }

    /**
     * Bind JWT decoders to public keys.
     *
     * @return map (keyId -> decoder), sorted by keyId for readability
     */
    private Map<String, JwtDecoder> createJwtDecoders(Map<String, RSAPublicKey> keyById) {
        return keyById.entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        mapEntry -> JwkUtils.createJwtDecoder(mapEntry.getValue()),
                        (decoder1, decoder2) -> {
                            throw new IllegalStateException("Multiple JWT decoders for the same keyId");
                        },
                        TreeMap::new));
    }

    /**
     * Logs each upcoming retry (cannot find out the failed URL because JWK suppliers are abstract).
     *
     * @param event event  the retry event
     */
    private void handleJwkRetryEvent(RetryOnRetryEvent event) {
        log.error("Attempt #{} to obtain JWK failed (will retry in {}): {}",
                event.getNumberOfRetryAttempts(),
                TimeUtils.humanFormatDuration(event.getWaitInterval()),
                event.getLastThrowable(),
                event.getLastThrowable());
    }

    /**
     * Sends alert after the last failed retry (cannot find out the failed URL because JWK suppliers are abstract).
     *
     * @param event event  the error event
     */
    private void handleJwkErrorEvent(RetryOnErrorEvent event) {
        log.error("Attempt #{} to obtain JWK failed (no more retries left): {}",
                // actually this is the total number of attempts, including the very first one
                event.getNumberOfRetryAttempts(),
                event.getLastThrowable(),
                // goes to logger implicitly, for stack trace
                event.getLastThrowable());
        alerter.accept(event.getLastThrowable());
    }

    /**
     * Logs each upcoming retry (cannot find out the failed URL because RSA suppliers are abstract).
     *
     * @param event event  the retry event
     */
    private void handleRsaRetryEvent(RetryOnRetryEvent event) {
        log.error("Attempt #{} to obtain RSA key failed (will retry in {}): {}",
                // starts with 1 because this handler is called before the 1st retry
                event.getNumberOfRetryAttempts(),
                TimeUtils.humanFormatDuration(event.getWaitInterval()),
                event.getLastThrowable(),
                // goes to logger implicitly, for stack trace
                event.getLastThrowable());
    }

    /**
     * Sends alert after the last failed retry (cannot find out the failed URL because RSA suppliers are abstract).
     *
     * @param event event  the error event
     */
    private void handleRsaErrorEvent(RetryOnErrorEvent event) {
        log.error("Attempt #{} to obtain RSA key failed (no more retries left): {}",
                // actually this is the total number of attempts, including the very first one
                event.getNumberOfRetryAttempts(),
                event.getLastThrowable(),
                // goes to logger implicitly, for stack trace
                event.getLastThrowable());
        alerter.accept(event.getLastThrowable());
    }

}
