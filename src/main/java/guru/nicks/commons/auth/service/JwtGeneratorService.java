package guru.nicks.commons.auth.service;

import guru.nicks.commons.auth.impl.JwtGeneratorServiceImpl;
import guru.nicks.commons.exception.http.UnauthorizedException;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

/**
 * Generates JWT for internal service-to-service REST calls.
 *
 * @see JwtGeneratorServiceImpl
 */
public interface JwtGeneratorService {

    /**
     * @return (public) keys used by this service to sign JWT tokens
     */
    JWKSet getJwks();

    /**
     * If {@code basicAuthHeader} contains valid client credentials, generates a JWT with parameters passed to
     * constructor.
     *
     * @param basicAuthHeader in the form of {@code Basic Base64-encoded-clientId:clientSecret}, as per
     *                        <a href="http://tools.ietf.org/html/rfc6749#section-4.4">OAuth2 spec</a>
     * @param formData        form data with {@code grant_type=client_credentials}
     * @return access token
     * @throws UnauthorizedException if {@code basicAuthHeader} is invalid or grant type is not 'client_credentials'
     */
    OAuth2AccessToken generateAccessToken(String basicAuthHeader, MultiValueMap<String, String> formData);

}
