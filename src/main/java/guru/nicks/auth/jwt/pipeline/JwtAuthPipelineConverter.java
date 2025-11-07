package guru.nicks.auth.jwt.pipeline;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;

import static guru.nicks.validation.dsl.ValiDsl.checkNotNull;

/**
 * Converts JWT to {@link Authentication} holding {@link OAuth2AuthenticatedPrincipal} or its subclass. Resembles
 * Spring's native {@link JwtBearerTokenAuthenticationConverter} but uses another user principal class and leverages
 * {@link JwtAuthPipeline}.
 *
 * @see guru.nicks.security.HttpSecurityConfigurer#withJwtAuthentication(Converter)
 */
@RequiredArgsConstructor
public class JwtAuthPipelineConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @NonNull // Lombok creates runtime nullness check for this own annotation only
    private final JwtAuthPipeline<? extends OAuth2AuthenticatedPrincipal> jwtAuthPipeline;

    /**
     * Called from {@link JwtAuthenticationProvider#authenticate(Authentication)} after successful JWT parsing (i.e.
     * signature/expiration check).
     *
     * @throws IllegalArgumentException if the result of JWT conversion is {@code null}
     */
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        OAuth2AuthenticatedPrincipal userPrincipal = checkNotNull(
                jwtAuthPipeline.apply(jwt).getOutput(), "user principal");

        var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());
        return new BearerTokenAuthentication(userPrincipal, accessToken, userPrincipal.getAuthorities());
    }

}
