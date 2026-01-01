package guru.nicks.commons.auth.impl;

import guru.nicks.commons.auth.domain.BasicAuthCredentials;
import guru.nicks.commons.auth.domain.CustomJwtClaim;
import guru.nicks.commons.auth.domain.OAuth2Provider;
import guru.nicks.commons.auth.service.JwtGeneratorService;
import guru.nicks.commons.exception.http.UnauthorizedException;
import guru.nicks.commons.utils.UuidUtils;
import guru.nicks.commons.utils.auth.AuthUtils;
import guru.nicks.commons.utils.json.JwkUtils;
import guru.nicks.commons.utils.json.JwtUtils;

import am.ik.yavi.meta.ConstraintArguments;
import com.github.f4b6a3.uuid.UuidCreator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static guru.nicks.commons.validation.dsl.ValiDsl.check;
import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotBlank;
import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotNull;

@Slf4j
public class JwtGeneratorServiceImpl implements JwtGeneratorService {

    private final OAuth2Provider oauth2Provider;
    private final Duration accessTokenTtl;
    private final Set<String> authorities;

    private final JWK jwk;
    private final JWSSigner signer;
    private final JWSHeader header;

    @Getter // no 'onMethod_ = @Override', otherwise apidocs are not generated
    private final JWKSet jwks;

    @ConstraintArguments
    public JwtGeneratorServiceImpl(OAuth2Provider oauth2Provider, Duration accessTokenTtl, String pem,
            Collection<String> authorities) {
        this.oauth2Provider = checkNotNull(oauth2Provider, _JwtGeneratorServiceImplArgumentsMeta.OAUTH2PROVIDER.name());
        checkNotBlank(oauth2Provider.getTokenUrl(), OAuth2Provider.Fields.tokenUrl);
        checkNotBlank(oauth2Provider.getClientId(), OAuth2Provider.Fields.clientId);
        checkNotBlank(oauth2Provider.getClientSecret(), OAuth2Provider.Fields.clientSecret);

        this.accessTokenTtl = checkNotNull(accessTokenTtl, _JwtGeneratorServiceImplArgumentsMeta.ACCESSTOKENTTL.name());
        check(accessTokenTtl, _JwtGeneratorServiceImplArgumentsMeta.ACCESSTOKENTTL.name()).constraint(
                Duration::isPositive, "must be positive");

        checkNotBlank(pem, _JwtGeneratorServiceImplArgumentsMeta.PEM.name());
        jwk = JwkUtils.parsePemToJwk(pem);
        jwks = new JWKSet(jwk);

        check(authorities, _JwtGeneratorServiceImplArgumentsMeta.AUTHORITIES.name()).notEmpty();
        this.authorities = Set.copyOf(authorities);

        try {
            signer = new RSASSASigner(jwk.toRSAKey());
        } catch (JOSEException e) {
            throw new SecurityException("Failed to create JWS signer: " + e.getMessage(), e);
        }

        // RS256 is used pretty much everywhere
        header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(jwk.getKeyID())
                .build();
    }

    @Override
    public OAuth2AccessToken generateAccessToken(String basicAuthHeader, MultiValueMap<String, String> formData) {
        String clientId;

        try {
            BasicAuthCredentials clientIdAndSecret = AuthUtils.parseBasicAuthHeader(basicAuthHeader);

            String grantType = formData.getFirst("grant_type");
            check(grantType, "grant_type")
                    .notBlank()
                    .constraint("client_credentials"::equals, "unsupported");

            clientId = clientIdAndSecret.getUsername();
            // don't disclose whether username is invalid, or password, or both
            check(clientId, "client ID and/or secret")
                    .notBlank()
                    .constraint(oauth2Provider.getClientId()::equals, "invalid");

            check(clientIdAndSecret.getPassword(), "client ID and/or secret")
                    .notBlank()
                    .constraint(oauth2Provider.getClientSecret()::equals, "invalid");
        } catch (Exception e) {
            throw new UnauthorizedException();
        }

        return generateInternalAccessToken();
    }

    /**
     * Called after all the security checks have passed. Therefore, <b>not public</b>.
     *
     * @return access token
     */
    private OAuth2AccessToken generateInternalAccessToken() {
        // 'no roles' must result in null map, so the claim will be omitted, otherwise it's in Keycloak format:
        // {"resource_access":  {"clientId": {"roles": [...]}}}
        Map<String, ?> authoritiesClaim = authorities.isEmpty()
                ? null
                : Map.of(oauth2Provider.getClientId(),
                        Map.of(CustomJwtClaim.KEYCLOAK_ROLES.getJwtName(), Set.copyOf(authorities)));

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(accessTokenTtl);
        JWTClaimsSet claims = buildClaims(oauth2Provider.getClientId(), issuedAt, expiresAt, authoritiesClaim);

        SignedJWT jwt = JwtUtils.createSignedJwt(header, signer, claims, jwk.toPublicJWK().toRSAKey());
        var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.serialize(), issuedAt, expiresAt);

        checkNotNull(token.getExpiresAt(), "expiresAt");
        check(token.getIssuedAt(), "issuedAt").before(token.getExpiresAt());

        log.info("Generated internal access token for IP '{}'", claims.getClaim("clientAddress"));
        return token;
    }

    /**
     * Very close to what Keycloak generates, for interoperability.
     */
    private JWTClaimsSet buildClaims(String clientId, Instant issuedAt, Instant expiresAt,
            @Nullable Map<String, ?> authorities) {
        return new JWTClaimsSet.Builder()
                // random
                .jwtID(UuidUtils.generateUuidV4().toString())
                // Keycloak puts UUID here, not clientId. So, clientId is converted to SHA-1 and then to UUID v5.
                .subject(UuidCreator.getNameBasedSha1(clientId).toString())
                // AZP (no AUD - Keycloak doesn't set it for Client Credentials grant)
                .claim(CustomJwtClaim.AUTHORIZED_PARTY.getJwtName(), clientId)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                //
                // non-standard claims borrowed from Keycloak
                .claim("typ", AuthUtils.BEARER_AUTH_TYPE)
                .claim("scope", "roles")
                .claim(CustomJwtClaim.KEYCLOAK_RESOURCE_ACCESS.getJwtName(), authorities)
                .claim("client_id", clientId)
                // brittle claim, depends on LogContext populated elsewhere
                //.claim("clientAddress", LogContext.REMOTE_IP.find().orElse(null))
                //
                .build();
    }

}
