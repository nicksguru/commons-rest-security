package guru.nicks.commons.auth.jwt.pipeline;

import guru.nicks.commons.utils.json.JwtUtils;

import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;

/**
 * Restricts JWT AZP/AUD claims (throws {@link BadJwtException}). The idea is to accept tokens issued for this
 * application only. For example, Google signs tokens for all apps with the same signature, in which case AZP/AUD
 * filtering is a must.
 * <p>
 * Doesn't need or create a user principal, so passing {@code null} is OK.
 */
@RequiredArgsConstructor
public class RestrictJwtAudienceStep<T> extends JwtAuthPipeline.Step<T> {

    /**
     * If not empty, defines the only allowed JWT AZP claims (if AZP is empty, AUD claim is checked).
     */
    private final Set<String> onlyJwtAudience;

    @Override
    public T apply(Jwt jwt, T userPrincipal) {
        // empty means ANY audience is allowed
        if (CollectionUtils.isEmpty(onlyJwtAudience)) {
            return userPrincipal;
        }

        Set<String> audience = JwtUtils.retrieveAzpOrAud(jwt);

        if (!CollectionUtils.containsAny(audience, onlyJwtAudience)) {
            throw new BadJwtException("JWT audience not accepted");
        }

        return userPrincipal;
    }

}
