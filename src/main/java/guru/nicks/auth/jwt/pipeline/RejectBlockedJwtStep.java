package guru.nicks.auth.jwt.pipeline;

import guru.nicks.exception.auth.AuthTokenBlockedException;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.function.Predicate;

/**
 * Rejects blocked tokens (throws {@link AuthTokenBlockedException}).
 * <p>
 * This authpipeline doesn't need ot create a user principal, so passing {@code null} is OK.
 */
@RequiredArgsConstructor
@Slf4j
public class RejectBlockedJwtStep<T> extends JwtAuthPipeline.Step<T> {

    /**
     * Accepts JWT value as a string, returns {@code true} if it's blocked.
     */
    @NonNull // Lombok creates runtime nullness check for this own annotation only
    private final Predicate<String> isBlockedToken;

    @Override
    public T apply(Jwt jwt, T userPrincipal) {
        if (isBlockedToken.test(jwt.getTokenValue())) {
            throw new AuthTokenBlockedException();
        }

        return userPrincipal;
    }

}
