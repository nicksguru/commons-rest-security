package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.jwt.pipeline.RejectUnsignedJwtStep;
import guru.nicks.commons.cucumber.world.TextWorld;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.DataTableType;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.when;

/**
 * Step definitions for testing {@link RejectUnsignedJwtStep}.
 */
@RequiredArgsConstructor
public class RejectUnsignedJwtSteps {

    // DI
    private final TextWorld textWorld;

    @Mock
    private Jwt mockJwt;
    private AutoCloseable closeableMocks;

    private RejectUnsignedJwtStep<UserDetails> rejectUnsignedJwtStep;
    private UserDetails inputUserPrincipal;
    private UserDetails resultUserPrincipal;

    @DataTableType
    public JwtConfig createJwtConfig(Map<String, String> entry) {
        return JwtConfig.builder()
                .algorithm(StringUtils.isNotBlank(entry.get("algorithm"))
                        ? entry.get("algorithm")
                        : null)
                .username(StringUtils.isNotBlank(entry.get("username"))
                        ? entry.get("username")
                        : null)
                .id(StringUtils.isNotBlank(entry.get("id"))
                        ? entry.get("id")
                        : null)
                .expectedResult(StringUtils.isNotBlank(entry.get("expectedResult"))
                        ? entry.get("expectedResult")
                        : null)
                .build();
    }

    @Before
    public void beforeEachScenario() {
        closeableMocks = MockitoAnnotations.openMocks(this);
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();
    }

    @Given("a reject unsigned JWT step")
    public void aRejectUnsignedJwtStep() {
        rejectUnsignedJwtStep = new RejectUnsignedJwtStep();
    }

    @Given("a JWT token with signature algorithm {string}")
    public void aJwtTokenWithSignatureAlgorithm(String algorithm) {
        var headers = new HashMap<String, Object>();
        headers.put("alg", algorithm);
        mockJwt = createMockJwtWithHeaders(headers);
    }

    @Given("a JWT token with missing signature algorithm header")
    public void aJwtTokenWithMissingSignatureAlgorithmHeader() {
        // intentionally not adding 'alg' header
        var headers = new HashMap<String, Object>();
        mockJwt = createMockJwtWithHeaders(headers);
    }

    @Given("a JWT token with null signature algorithm header")
    public void aJwtTokenWithNullSignatureAlgorithmHeader() {
        var headers = new HashMap<String, Object>();
        headers.put("alg", null);
        mockJwt = createMockJwtWithHeaders(headers);
    }

    @Given("an existing user principal with username {string} for JWT signature algorithm validation")
    public void anExistingUserPrincipalWithUsernameForJwtSignatureAlgorithmValidation(String username) {
        inputUserPrincipal = User.builder()
                .username(username)
                // cannot be empty in constructor
                .password(username)
                .build();
    }

    @Given("an existing user principal with username {string}")
    public void anExistingUserPrincipalWithUsername(String username) {
        inputUserPrincipal = User.builder()
                .username(username)
                // cannot be empty in constructor
                .password(username)
                .build();
    }

    @Given("no existing user principal for JWT signature algorithm validation")
    public void noExistingUserPrincipalForJwtSignatureAlgorithmValidation() {
        inputUserPrincipal = null;
    }

    @When("the reject unsigned JWT step is applied")
    public void theRejectUnsignedJwtStepIsApplied() {
        textWorld.setLastException(catchThrowable(() ->
                resultUserPrincipal = rejectUnsignedJwtStep.apply(mockJwt, inputUserPrincipal)));
    }

    @Then("the user principal should be returned with username {string} after signature algorithm validation")
    public void theUserPrincipalShouldBeReturnedWithUsername(String expectedUsername) {
        assertThat(resultUserPrincipal)
                .as("result user principal")
                .isNotNull();

        assertThat(resultUserPrincipal.getUsername())
                .as("username")
                .isEqualTo(expectedUsername);

        assertThat(resultUserPrincipal)
                .as("user principal reference")
                .isSameAs(inputUserPrincipal);
    }

    @Then("the user principal should be null after signature algorithm validation")
    public void theUserPrincipalShouldBeNullAfterSignatureAlgorithmValidation() {
        assertThat(resultUserPrincipal)
                .as("result user principal")
                .isNull();
    }

    @Then("the JWT signature algorithm validation result should be {string}")
    public void theJwtSignatureAlgorithmValidationResultShouldBe(String expectedResult) {
        var exception = textWorld.getLastException();

        if ("success".equals(expectedResult)) {
            assertThat(exception)
                    .as("thrown exception")
                    .isNull();

            assertThat(resultUserPrincipal)
                    .as("result user principal")
                    .isSameAs(inputUserPrincipal);
        } else if ("BadJwtException".equals(expectedResult)) {
            assertThat(exception)
                    .as("thrown exception")
                    .isNotNull()
                    .isInstanceOf(BadJwtException.class);

            assertThat(exception.getMessage())
                    .as("exception message")
                    .isEqualTo("Unencrypted JWT not allowed");
        }
    }

    /**
     * Creates a mock JWT with specified headers.
     */
    private Jwt createMockJwtWithHeaders(Map<String, Object> headers) {
        var jwt = Jwt.withTokenValue("test-token")
                .header("typ", "JWT")
                .claim("sub", "testuser")
                .claim("iat", Instant.now())
                .claim("exp", Instant.now().plusSeconds(3600))
                .build();

        // mock the getHeaders() method to return our custom headers
        when(mockJwt.getHeaders())
                .thenReturn(headers);
        when(mockJwt.getTokenValue())
                .thenReturn(jwt.getTokenValue());
        when(mockJwt.getClaims())
                .thenReturn(jwt.getClaims());

        return mockJwt;
    }

    /**
     * Data table representation for JWT configuration.
     */
    @Value
    @Builder
    public static class JwtConfig {

        String algorithm;
        String username;
        String id;
        String expectedResult;

    }

}
