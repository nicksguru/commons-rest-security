package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.jwt.pipeline.RestrictUserEmailStep;
import guru.nicks.commons.cucumber.world.TextWorld;

import io.cucumber.java.DataTableType;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;

@RequiredArgsConstructor
public class RestrictUserEmailSteps {

    // DI
    private final TextWorld textWorld;

    private TestRestrictUserEmailStep step;
    private String userEmail;

    @DataTableType
    public AllowedEmailPattern createAllowedEmailPattern(Map<String, String> row) {
        return AllowedEmailPattern.builder()
                .pattern(row.get("pattern"))
                .build();
    }

    @Given("the following email allow-list:")
    public void theFollowingEmailAllowList(List<AllowedEmailPattern> patterns) {
        var patternStrings = patterns.stream()
                .filter(Objects::nonNull)
                .map(AllowedEmailPattern::getPattern)
                .filter(Objects::nonNull)
                .map(p -> StringUtils.split(p, ','))
                .flatMap(Arrays::stream)
                .map(String::strip)
                .toList();
        step = new TestRestrictUserEmailStep(patternStrings);
    }

    @And("the user has the email {string}")
    public void theUserHasTheEmail(String email) {
        this.userEmail = StringUtils.isNotBlank(email)
                ? email
                : null;
    }

    @When("the user email is checked")
    public void theUserEmailIsChecked() {
        var lastException = catchThrowable(() ->
                step.apply(mock(Jwt.class), userEmail));
        textWorld.setLastException(lastException);
    }

    /**
     * A test implementation of the abstract {@link RestrictUserEmailStep}.
     */
    private static class TestRestrictUserEmailStep extends RestrictUserEmailStep<String> {

        public TestRestrictUserEmailStep(@Nullable Collection<String> allowedEmailPatterns) {
            super(allowedEmailPatterns);
        }

        @Nullable
        @Override
        protected String getUserEmail(@Nonnull String userPrincipal) {
            return userPrincipal;
        }

    }

    @Value
    @Builder
    public static class AllowedEmailPattern {

        String pattern;

    }

}
