package guru.nicks.auth.jwt;

import guru.nicks.designpattern.pipeline.Pipeline;
import guru.nicks.designpattern.pipeline.PipelineState;
import guru.nicks.designpattern.pipeline.PipelineStep;

import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Collection;
import java.util.Optional;

/**
 * Pipeline which accepts {@link Jwt} and returns {@code T} (presumably a user principal).
 *
 * @param <T> user principal type
 * @see #apply(Jwt)
 */
@Slf4j
public class JwtAuthPipeline<T> extends Pipeline<Jwt, T, JwtAuthPipeline.Step<T>> {

    /**
     * @see Pipeline#Pipeline(Collection)
     */
    public JwtAuthPipeline(Collection<? extends Step<T>> steps) {
        super(steps);
    }

    /**
     * Spring routes {@link InsufficientAuthenticationException} - and not others - to {@link AuthenticationEntryPoint};
     * all other exceptions result in non-informative HTTP status 500. Therefore, this method wraps all exceptions in
     * {@link InsufficientAuthenticationException} and issues a brief warning message (not an error message because most
     * probably this is an invalid JWT, not an application error, and should not be treated by log analyzers as a
     * problem).
     *
     * @param jwt JWT
     * @return T
     */
    @Override
    public PipelineState<Jwt, T> apply(@Nullable Jwt jwt) {
        try {
            return super.apply(jwt);
        } catch (Exception e) {
            log.warn("Authentication failed{} at {}",
                    // don't print null message as 'null'
                    Optional.ofNullable(e.getMessage())
                            .filter(StringUtils::isNotBlank)
                            .map(msg -> ": '" + msg + "'")
                            .orElse(""),
                    ArrayUtils.isEmpty(e.getStackTrace())
                            ? "<unknown>"
                            : e.getStackTrace()[0]);
            throw new InsufficientAuthenticationException(e.getMessage(), e);
        }
    }

    /**
     * A dedicated class helps avoid declaring generic types in each step's declaration.
     */
    public abstract static class Step<T> extends PipelineStep<Jwt, T> {
    }

}
