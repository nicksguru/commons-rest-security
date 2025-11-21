package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.domain.CustomJwtClaim;
import guru.nicks.commons.auth.domain.OAuth2Provider;
import guru.nicks.commons.auth.impl.JwtGeneratorServiceImpl;
import guru.nicks.commons.cucumber.world.TextWorld;
import guru.nicks.commons.utils.auth.AuthUtils;
import guru.nicks.commons.utils.crypto.PemUtils;
import guru.nicks.commons.utils.json.JwkUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

@RequiredArgsConstructor
public class JwtGeneratorServiceSteps {

    // DI
    private final TextWorld textWorld;

    private String clientId;
    private JwtGeneratorServiceImpl jwtGeneratorService;
    private OAuth2AccessToken generatedToken;

    private String pemKeyPair;
    private JWSVerifier verifier;

    @Given("a PEM encoded random key pair")
    public void aPemEncodedRandomKeyPair() throws Exception {
        // generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String privateKeyPem = PemUtils.encodeToPem(keyPair.getPrivate());
        String publicKeyPem = PemUtils.encodeToPem(keyPair.getPublic());
        // combine private and public key PEMs
        pemKeyPair = privateKeyPem + "\n" + publicKeyPem;
    }

    @Given("JWT generator service is initialized with valid configuration")
    public void jwtGeneratorServiceIsInitializedWithValidConfiguration() throws Exception {
        var authProvider = OAuth2Provider.builder()
                .id(OAuth2Provider.INTERNAL_PROVIDER_ID)
                .tokenUrl("http://localhost:8080/oauth/token")
                .clientId(OAuth2Provider.INTERNAL_PROVIDER_ID)
                .clientSecret("test-secret")
                .build();

        jwtGeneratorService = new JwtGeneratorServiceImpl(authProvider, Duration.ofMinutes(30),
                pemKeyPair, Set.of("test-authority"));

        // setup verification tools
        JWK jwk = JwkUtils.parsePemToJwk(pemKeyPair);
        verifier = new RSASSAVerifier(jwk.toPublicJWK().toRSAKey());
    }

    @When("an access token is requested with valid basic auth header {string} and grant type {string}")
    public void anAccessTokenIsRequestedWithValidBasicAuthHeaderAndGrantType(String basicAuthHeader,
            String grantType) {
        // for checking user roles afterward (they're bound to the client ID in the JWT, not to the user ID)
        clientId = AuthUtils.parseBasicAuthHeader(basicAuthHeader).getUsername();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", grantType);

        textWorld.setLastException(catchThrowable(() ->
                generatedToken = jwtGeneratorService.generateAccessToken(basicAuthHeader, formData)));
    }

    @When("an access token is requested with invalid basic auth header {string} and grant type {string}")
    public void anAccessTokenIsRequestedWithInvalidBasicAuthHeaderAndGrantType(String basicAuthHeader,
            String grantType) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", grantType);

        textWorld.setLastException(catchThrowable(() ->
                generatedToken = jwtGeneratorService.generateAccessToken(basicAuthHeader, formData)));
    }

    @Then("the generated token should be valid")
    public void theGeneratedTokenShouldBeValid() throws JOSEException, ParseException {
        assertThat(generatedToken)
                .as("generatedToken")
                .isNotNull();

        SignedJWT jwt = SignedJWT.parse(generatedToken.getTokenValue());

        assertThat(jwt.verify(verifier))
                .as("tokenVerification")
                .isTrue();
    }

    @Then("the token should contain the {string} authority")
    public void theTokenShouldContainTheRole(String authority) throws ParseException {
        SignedJWT jwt = SignedJWT.parse(generatedToken.getTokenValue());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        Map<String, Object> resourceAccess =
                (Map<String, Object>) claims.getClaim(CustomJwtClaim.KEYCLOAK_RESOURCE_ACCESS.getJwtName());
        assertThat(resourceAccess)
                .as("resourceAccess")
                .isNotNull();

        Map<String, Object> privateClient = (Map<String, Object>) resourceAccess.get(clientId);
        assertThat(privateClient)
                .as("privateClient")
                .isNotNull();

        List<String> roles = (List<String>) privateClient.get(CustomJwtClaim.KEYCLOAK_ROLES.getJwtName());
        assertThat(roles)
                .as("roles")
                .contains(authority);
    }

    @Then("the token should have the correct client ID")
    public void theTokenShouldHaveTheCorrectClientId() throws ParseException {
        SignedJWT jwt = SignedJWT.parse(generatedToken.getTokenValue());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        assertThat(claims.getClaimAsString(CustomJwtClaim.AUTHORIZED_PARTY.getJwtName()))
                .as(CustomJwtClaim.AUTHORIZED_PARTY.getJwtName() + " claim")
                .isNotBlank();

        assertThat(claims.getClaimAsString("client_id"))
                .as("client_id claim")
                .isEqualTo(clientId);
    }

    @Then("the token should have a valid expiration time")
    public void theTokenShouldHaveAValidExpirationTime() {
        assertThat(generatedToken.getExpiresAt())
                .as("expiresAt")
                .isAfter(Instant.now());

        assertThat(generatedToken.getIssuedAt())
                .as("issuedAt")
                .isBefore(generatedToken.getExpiresAt());
    }

}
