package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.jwt.pipeline.RejectBlockedJwtStep;
import guru.nicks.commons.cucumber.world.TextWorld;
import guru.nicks.commons.exception.auth.AuthTokenBlockedException;

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
import org.mockito.Spy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Step definitions for testing {@link RejectBlockedJwtStep}.
 */
@RequiredArgsConstructor
public class RejectBlockedJwtSteps {

    // DI
    private final TextWorld textWorld;

    @Mock
    private Jwt mockJwt;
    @Spy
    private Predicate<String> spyPredicate;
    private AutoCloseable closeableMocks;

    private RejectBlockedJwtStep<UserDetails> rejectBlockedJwtStep;
    private UserDetails inputUserPrincipal;
    private UserDetails resultUserPrincipal;

    private Predicate<String> isBlockedTokenPredicate;

    @DataTableType
    public BlockingConfig createBlockingConfig(Map<String, String> entry) {
        return BlockingConfig.builder()
                .tokenValue(StringUtils.isNotBlank(entry.get("tokenValue"))
                        ? entry.get("tokenValue")
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
                .blockedPattern(StringUtils.isNotBlank(entry.get("blockedPattern"))
                        ? entry.get("blockedPattern")
                        : null)
                .predicateResult(StringUtils.isNotBlank(entry.get("predicateResult"))
                        ? Boolean.parseBoolean(entry.get("predicateResult"))
                        : false)
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

    @Given("a reject blocked JWT step with predicate returning true")
    public void aRejectBlockedJwtStepWithPredicateReturningTrue() {
        isBlockedTokenPredicate = token -> true;
        rejectBlockedJwtStep = new RejectBlockedJwtStep(isBlockedTokenPredicate);
    }

    @Given("a reject blocked JWT step with predicate returning false")
    public void aRejectBlockedJwtStepWithPredicateReturningFalse() {
        isBlockedTokenPredicate = token -> false;
        rejectBlockedJwtStep = new RejectBlockedJwtStep(isBlockedTokenPredicate);
    }

    @Given("a reject blocked JWT step with predicate that blocks tokens containing {string}")
    public void aRejectBlockedJwtStepWithPredicateThatBlocksTokensContaining(String blockedPattern) {
        isBlockedTokenPredicate = token ->
                (token != null) && token.contains(blockedPattern);
        rejectBlockedJwtStep = new RejectBlockedJwtStep(isBlockedTokenPredicate);
    }

    @Given("a reject blocked JWT step with predicate that blocks empty or null tokens")
    public void aRejectBlockedJwtStepWithPredicateThatBlocksEmptyOrNullTokens() {
        isBlockedTokenPredicate = token ->
                (token == null) || token.isEmpty();
        rejectBlockedJwtStep = new RejectBlockedJwtStep(isBlockedTokenPredicate);
    }

    @Given("a reject blocked JWT step with spy predicate returning false")
    public void aRejectBlockedJwtStepWithSpyPredicateReturningFalse() {
        spyPredicate = spy(Predicate.class);
        when(spyPredicate.test(anyString()))
                .thenReturn(false);

        rejectBlockedJwtStep = new RejectBlockedJwtStep(spyPredicate);
    }

    @Given("a JWT token with value {string} for JWT block check")
    public void aJwtTokenWithValueForJwtBlockCheck(String tokenValue) {
        var actualTokenValue = StringUtils.isBlank(tokenValue)
                ? null
                : tokenValue;
        mockJwt = createMockJwtWithTokenValue(actualTokenValue);
    }

    @Given("an existing user principal with username {string} for JWT block check")
    public void anExistingUserPrincipalWithUsername(String username) {
        inputUserPrincipal = User.builder()
                .username(username)
                // cannot be empty in constructor
                .password(username)
                .build();
    }

    @Given("no existing user principal")
    public void noExistingUserPrincipal() {
        inputUserPrincipal = null;
    }

    @When("the reject blocked JWT step is applied")
    public void theRejectBlockedJwtStepIsApplied() {
        textWorld.setLastException(catchThrowable(() ->
                resultUserPrincipal = rejectBlockedJwtStep.apply(mockJwt, inputUserPrincipal)));
    }

    @Then("the result should be {string}")
    public void theResultShouldBe(String expectedResult) {
        var exception = textWorld.getLastException();

        if ("success".equals(expectedResult)) {
            assertThat(exception)
                    .as("thrown exception")
                    .isNull();

            assertThat(resultUserPrincipal)
                    .as("result user principal")
                    .isSameAs(inputUserPrincipal);
        } else if ("exception".equals(expectedResult)) {
            assertThat(exception)
                    .as("thrown exception")
                    .isNotNull()
                    .isInstanceOf(AuthTokenBlockedException.class);
        }
    }

    @Then("the user principal should be returned with username {string} after JWT block check")
    public void theUserPrincipalShouldBeReturnedWithUsernameAfterJwtBlockCheck(String expectedUsername) {
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

    @Then("the user principal should be null after JWT block check")
    public void theUserPrincipalShouldBeNullAfterJwtBlockCheck() {
        assertThat(resultUserPrincipal)
                .as("result user principal")
                .isNull();
    }

    @Then("the exception should be of type {string} after JWT block check")
    public void theExceptionShouldBeOfTypeAfterJwtBlockCheck(String expectedExceptionType) {
        var exception = textWorld.getLastException();
        assertThat(exception)
                .as("thrown exception")
                .isNotNull();

        assertThat(exception.getClass().getSimpleName())
                .as("exception type")
                .isEqualTo(expectedExceptionType);
    }

    @Then("the predicate should have been called with {string}")
    public void thePredicateShouldHaveBeenCalledWith(String expectedTokenValue) {
        verify(spyPredicate).test(expectedTokenValue);
    }

    /**
     * Creates a mock JWT with specified token value.
     */
    private Jwt createMockJwtWithTokenValue(String tokenValue) {
        var jwtBuilder = Jwt.withTokenValue(tokenValue != null
                        ? tokenValue
                        : "default-token")
                .header("alg", "RS256")
                .header("typ", "JWT")
                .claim("sub", "testuser")
                .claim("iat", Instant.now())
                .claim("exp", Instant.now().plusSeconds(3600));

        var jwt = jwtBuilder.build();

        when(mockJwt.getTokenValue())
                .thenReturn(tokenValue);
        when(mockJwt.getHeaders())
                .thenReturn(jwt.getHeaders());
        when(mockJwt.getClaims())
                .thenReturn(jwt.getClaims());

        return mockJwt;
    }

    /**
     * Data table representation for JWT blocking configuration.
     */
    @Value
    @Builder
    public static class BlockingConfig {

        String tokenValue;

        String username;
        String id;

        String expectedResult;
        String blockedPattern;

        boolean predicateResult;
    }

}
