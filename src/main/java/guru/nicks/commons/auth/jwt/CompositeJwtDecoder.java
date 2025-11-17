package guru.nicks.commons.auth.jwt;

import guru.nicks.commons.designpattern.ChainOfResponsibility;
import guru.nicks.commons.designpattern.iterator.ThreadSafeListOffsetIterator;
import guru.nicks.commons.designpattern.pipeline.PipelineState;
import guru.nicks.commons.designpattern.pipeline.PipelineStep;
import guru.nicks.commons.designpattern.pipeline.PipelineStepFeature;
import guru.nicks.commons.utils.TimeUtils;
import guru.nicks.commons.utils.TransformUtils;

import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static guru.nicks.commons.validation.dsl.ValiDsl.check;
import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotNull;
import static org.apache.commons.lang3.ArrayUtils.INDEX_NOT_FOUND;

/**
 * Chain of Responsibility which invokes JWT decoders until one of them succeeds or the chain ends. Optimizes
 * performance by prioritizing the decoder that last successfully decoded a token. If {@link #atLeastOneKeyExpired()}
 * returns {@code true}, {@link JwtValidationException} is thrown immediately.
 */
@Slf4j
public class CompositeJwtDecoder implements JwtDecoder {

    /**
     * Error codes to pass to {@link JwtValidationException}.
     */
    private static final List<OAuth2Error> OAUTH_ERROR_CODES = List.of(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));

    @Getter
    private final List<JwtDecoder> jwtDecoders;

    /**
     * If not {@code null}, defines the moment when at least one of the public key expires, which means the whole chain
     * has expired too.
     *
     * @see #atLeastOneKeyExpired()
     */
    @Getter
    private final Instant expirationDate;

    private final JwtDecoderPipeline jwtDecoderPipeline;

    /**
     * Constructor.
     *
     * @param decoderById    map of decoder IDs to JWT decoders
     * @param expirationDate optional expiration date for the decoder chain
     */
    public CompositeJwtDecoder(Map<String, JwtDecoder> decoderById, @Nullable Instant expirationDate) {
        // needed for get(0) during decoding
        check(OAUTH_ERROR_CODES, "OAuth error codes").notEmpty();

        // validate no null keys or values
        decoderById.forEach((key, value) -> {
            checkNotNull(key, "decoder key");
            checkNotNull(value, "decoder value");
        });

        List<JwtDecoderPipeline.Step> steps = decoderById.entrySet()
                .stream()
                .map(mapEntry ->
                        JwtDecoderPipeline.Step.builder()
                                .name(mapEntry.getKey())
                                .jwtDecoder(mapEntry.getValue())
                                .build())
                .toList();
        jwtDecoderPipeline = new JwtDecoderPipeline(steps);

        jwtDecoders = TransformUtils.toList(steps, JwtDecoderPipeline.Step::getJwtDecoder);
        this.expirationDate = expirationDate;

        log.info("Chain of {} JWT decoder{} {}", jwtDecoders.size(), (jwtDecoders.size() == 1) ? "" : "s",
                Optional.ofNullable(expirationDate)
                        .map(instant -> "expires in "
                                + TimeUtils.humanFormatDuration(Duration.between(Instant.now(), instant))
                                + " (at " + instant + ")")
                        .orElse("never expires"));
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // save time - don't call all decoders
        if (StringUtils.isBlank(token)) {
            throw new JwtValidationException(OAUTH_ERROR_CODES.getFirst().getErrorCode(), OAUTH_ERROR_CODES);
        }

        if (atLeastOneKeyExpired()) {
            log.error("Expired JWT validation chain should not be called, it should be refreshed first");
            throw new JwtValidationException(OAUTH_ERROR_CODES.getFirst().getErrorCode(), OAUTH_ERROR_CODES);
        }

        Jwt jwt = jwtDecoderPipeline.apply(token).getOutput();

        if (jwt == null) {
            throw new JwtValidationException(OAUTH_ERROR_CODES.getFirst().getErrorCode(), OAUTH_ERROR_CODES);
        }

        return jwt;
    }

    /**
     * Checks if {@link #getExpirationDate()} is not in the future, i.e. if at least one of the public keys has
     * expired.
     *
     * @return {@code true} if chain has expired
     */
    public boolean atLeastOneKeyExpired() {
        return (expirationDate != null) && !expirationDate.isAfter(Instant.now());
    }

    private static class JwtDecoderPipeline extends ChainOfResponsibility<String, Jwt, JwtDecoderPipeline.Step> {

        /**
         * Index in {@link #getSteps()} to try first and thus hopefully save time. Once set to a something which is not
         * {@link ArrayUtils#INDEX_NOT_FOUND}, never becomes altered.
         */
        private final AtomicInteger priorityDecoderIndex = new AtomicInteger(INDEX_NOT_FOUND);

        public JwtDecoderPipeline(Collection<? extends Step> steps) {
            super(steps);
        }

        /**
         * Creates a special iterator which starts with the 'priority decoder' and then rolls over list end.
         *
         * @return step iterator
         */
        @Override
        public Iterator<Step> iterator() {
            return new ThreadSafeListOffsetIterator<>(getSteps(), priorityDecoderIndex.get());
        }

        /**
         * Upon decoding success, initializes priority decoder.
         */
        @Override
        public PipelineState<String, Jwt> apply(@Nullable String token) {
            PipelineState<String, Jwt> pipelineState = super.apply(token);

            // if there's no priority decoder yet, the list was iterated from its beginning (offset 0), therefore the
            // number of steps executed corresponds to the item index
            if ((pipelineState.getOutput() != null) && (priorityDecoderIndex.get() == INDEX_NOT_FOUND)) {
                int index = pipelineState.getExecutedStepCount() - 1;

                // if some other thread has already set a value, don't care
                if (index >= 0) {
                    if (priorityDecoderIndex.compareAndSet(INDEX_NOT_FOUND, index)) {
                        log.info("Marked decoder '{}' as try-first to speed up performance",
                                getSteps().get(index).getName());
                    }
                }
            }

            return pipelineState;
        }

        /**
         * Decodes JWT. This operation is not cacheable because JWTs expire. Strictly speaking, it's OK to cache the
         * result during the individual JWT lifetime, but this would make the logic complicated and error-prone -
         * there's no reliable cache key (any checksum may have collisions), and using JWTs themselves as cache keys is
         * insecure.
         * <p>
         * The class is public because it contains a getter annotated with
         * {@link PipelineStepFeature @PipelineStepFeature}.
         */
        @Builder
        public static class Step extends PipelineStep<String, Jwt> {

            /**
             * Key ID is seen as step name during logging.
             */
            @Getter // no 'onMethod_ = @Override', otherwise apidocs are not generated
            @NonNull // Lombok creates runtime nullness check for this own annotation only
            private final String name;

            @Getter
            @NonNull // Lombok creates runtime nullness check for this own annotation only
            private final JwtDecoder jwtDecoder;

            /**
             * Decodes JWT.
             *
             * @param jwt                   JWT as string
             * @param alwaysNullAccumulator accumulator (unused in this case)
             * @return JWT decoded or {@code null} on any decoding failure (non-matching public key / JWT malformed /
             *         JWT expired / bug in the decoder), so next chain step, if any, will be invoked
             */
            @Nullable
            @Override
            public Jwt apply(String jwt, Jwt alwaysNullAccumulator) {
                try {
                    return jwtDecoder.decode(jwt);
                } catch (Exception e) {
                    if (log.isTraceEnabled()) {
                        log.trace("Failed to decode JWT with decoder '{}': {}", name, e.getMessage(), e);
                    }

                    return null;
                }
            }

        }

    }

}
