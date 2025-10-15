package guru.nicks.cucumber;

import guru.nicks.auth.jwt.pipeline.RestrictJwtAudienceStep;
import guru.nicks.cucumber.world.TextWorld;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Step definitions for testing {@link RestrictJwtAudienceSteps}.
 */
@RequiredArgsConstructor
public class RestrictJwtAudienceSteps {

    // DI
    private final TextWorld textWorld;

    @Mock
    private Jwt mockJwt;
    private AutoCloseable closeableMocks;

    private RestrictJwtAudienceStep<UserDetails> restrictJwtAudienceStep;
    private UserDetails inputUserPrincipal;
    private UserDetails resultUserPrincipal;

    @DataTableType
    public AudienceConfig createAudienceConfig(Map<String, String> entry) {
        return AudienceConfig.builder()
                .allowedAudiences(StringUtils.isNotBlank(entry.get("allowedAudiences"))
                        ? entry.get("allowedAudiences")
                        : null)
                .tokenAudience(StringUtils.isNotBlank(entry.get("tokenAudience"))
                        ? entry.get("tokenAudience")
                        : null)
                .azpClaim(StringUtils.isNotBlank(entry.get("azpClaim"))
                        ? entry.get("azpClaim")
                        : null)
                .audClaim(StringUtils.isNotBlank(entry.get("audClaim"))
                        ? entry.get("audClaim")
                        : null)
                .tokenAudiences(StringUtils.isNotBlank(entry.get("tokenAudiences"))
                        ? entry.get("tokenAudiences")
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

    @Given("a JWT audience restriction step with empty allowed audiences")
    public void aJwtAudienceRestrictionStepWithEmptyAllowedAudiences() {
        restrictJwtAudienceStep = new RestrictJwtAudienceStep(Collections.emptySet());
    }

    @Given("allowed JWT audiences {string}")
    public void allowedJwtAudiences(String allowedAudiences) {
        var audienceSet = parseAudienceString(allowedAudiences);
        restrictJwtAudienceStep = new RestrictJwtAudienceStep(audienceSet);
    }

    @Given("a JWT token with audience {string}")
    public void aJwtTokenWithAudience(String audience) {
        var audienceSet = parseAudienceString(audience);
        mockJwt = createMockJwt(audienceSet);
    }

    @Given("a JWT token with AZP claim {string} and AUD claim {string}")
    public void aJwtTokenWithAzpClaimAndAudClaim(String azpClaim, String audClaim) {
        // simulate JwtUtils behavior: if AZP is present, use it; otherwise use AUD
        Set<String> resultAudience;
        if (StringUtils.isNotBlank(azpClaim)) {
            resultAudience = parseAudienceString(azpClaim);
        } else if (StringUtils.isNotBlank(audClaim)) {
            resultAudience = parseAudienceString(audClaim);
        } else {
            resultAudience = Collections.emptySet();
        }

        mockJwt = createMockJwt(resultAudience);
    }

    @Given("a JWT token with multiple audiences {string}")
    public void aJwtTokenWithMultipleAudiences(String audiences) {
        var audienceSet = parseAudienceString(audiences);
        mockJwt = createMockJwt(audienceSet);
    }

    @Given("an existing user principal with username {string} for JWT audience restriction")
    public void anExistingUserPrincipalWithUsername(String username) {
        inputUserPrincipal = User.builder()
                .username(username)
                // cannot be empty in constructor
                .password(username)
                .build();
    }

    @Given("no existing user principal for JWT audience restriction")
    public void noExistingUserPrincipalForJwtAudienceRestriction() {
        inputUserPrincipal = null;
    }

    @When("the JWT audience restriction is applied")
    public void theJwtAudienceRestrictionIsApplied() {
        textWorld.setLastException(catchThrowable(() ->
                resultUserPrincipal = restrictJwtAudienceStep.apply(mockJwt, inputUserPrincipal)));
    }

    @Then("the user principal should be returned unchanged after JWT audience restriction")
    public void theUserPrincipalShouldBeReturnedUnchangedAfterJWTAudienceRestriction() {
        assertThat(resultUserPrincipal)
                .as("result user principal")
                .isSameAs(inputUserPrincipal);
    }

    @Then("the JWT audience restriction result should be {string}")
    public void theResultShouldBe(String expectedResult) {
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
                    .isEqualTo("JWT audience not accepted");
        } else {
            throw new AssertionError("Invalid expected result: '" + expectedResult + "'");
        }

    }

    @Then("the user principal should be null after audience restriction")
    public void theUserPrincipalShouldBeNullAfterJWTAudienceRestriction() {
        assertThat(resultUserPrincipal)
                .as("result user principal")
                .isNull();
    }

    /**
     * Creates a mock JWT with basic claims.
     */
    private Jwt createMockJwt(Set<String> aud) {
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", "testuser")
                .claim("iat", Instant.now())
                .claim("exp", Instant.now().plusSeconds(3600))
                .audience(aud)
                .build();
    }

    /**
     * Parses comma-separated audience string into a set.
     */
    private Set<String> parseAudienceString(String audienceString) {
        if (StringUtils.isBlank(audienceString)) {
            return Collections.emptySet();
        }

        return Arrays.stream(audienceString.split(","))
                .map(String::strip)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toSet());
    }

    /**
     * Data table representation for JWT audience configuration.
     */
    @Value
    @Builder
    public static class AudienceConfig {

        String allowedAudiences;
        String tokenAudience;

        String azpClaim;
        String audClaim;

        String tokenAudiences;
        String expectedResult;

    }

}
