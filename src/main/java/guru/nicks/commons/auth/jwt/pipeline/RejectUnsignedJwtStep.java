package guru.nicks.commons.auth.jwt.pipeline;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Objects;

/**
 * Checks JWT signature algorithm ('alg' header) - it must be present and must not equal 'none', otherwise
 * {@link BadJwtException} is thrown. Passing a JWT without a signature is a well-known attack vector.
 * <p>
 * This must be the very first step, so unsigned JWTs are never analyzed in any way. This step doesn't need a user
 * principal, so passing {@code null} is OK.
 */
public class RejectUnsignedJwtStep<T> extends JwtAuthPipeline.Step<T> {

    public T apply(Jwt jwt, T userPrincipal) {
        // missing header is treated as 'none', which means 'no signature' according to RFC
        String signatureAlgorithm = Objects.toString(jwt.getHeaders().get("alg"), "none");

        if (StringUtils.isBlank(signatureAlgorithm) || "none".equalsIgnoreCase(signatureAlgorithm)) {
            throw new BadJwtException("Unencrypted JWT not allowed");
        }

        return userPrincipal;
    }

}
