package guru.nicks.cucumber;

import guru.nicks.auth.jwt.pipeline.RestrictUsernameStep;
import guru.nicks.cucumber.world.TextWorld;

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

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;

@RequiredArgsConstructor
public class RestrictUsernameSteps {

    // DI
    private final TextWorld textWorld;

    private RestrictUsernameStep<String> step;
    private String username;

    @DataTableType
    public DeniedUsername createDeniedUsername(Map<String, String> row) {
        return DeniedUsername.builder()
                .username(row.get("username"))
                .build();
    }

    @Given("the following username deny-list:")
    public void theFollowingUsernameDenyList(List<DeniedUsername> deniedUsernames) {
        var usernames = deniedUsernames.stream()
                .map(DeniedUsername::getUsername)
                .toList();
        this.step = new TestRestrictUsernameStep(usernames);
    }

    @And("the user has the username {string}")
    public void theUserHasTheUsername(String username) {
        this.username = StringUtils.isNotBlank(username)
                ? username
                : null;
    }

    @When("the username is checked")
    public void theUsernameIsChecked() {
        var lastException = catchThrowable(() ->
                step.apply(mock(Jwt.class), username));
        textWorld.setLastException(lastException);
    }

    @Value
    @Builder
    public static class DeniedUsername {
        String username;
    }

    private static class TestRestrictUsernameStep extends RestrictUsernameStep<String> {

        public TestRestrictUsernameStep(List<String> forbiddenUsernames) {
            super(forbiddenUsernames);
        }

        @Nullable
        @Override
        protected String getUsername(@Nonnull String userPrincipal) {
            return userPrincipal;
        }

    }

}
