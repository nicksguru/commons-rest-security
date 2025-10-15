package guru.nicks.cucumber;

import guru.nicks.auth.jwt.CompositeJwtDecoder;
import guru.nicks.cucumber.world.JwtWorld;
import guru.nicks.cucumber.world.TextWorld;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.RequiredArgsConstructor;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RequiredArgsConstructor
public class CompositeJwtDecoderSteps {

    // DI
    private final JwtWorld jwtWorld;
    private final TextWorld textWorld;

    private CompositeJwtDecoder jwtDecoder;

    private AutoCloseable closeableMocks;
    @Mock
    private JwtDecoder jwtDecoder1;
    @Mock
    private JwtDecoder jwtDecoder2;

    /**
     * Applies local {@code @Mock/@Spy}.
     */
    @Before
    public void beforeEachScenario() {
        closeableMocks = MockitoAnnotations.openMocks(this);
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();
    }

    @Given("JWT token {string}")
    public void jwt_token(String token) {
        jwtWorld.setToken(token);
    }

    @Given("no decoders")
    public void no_decoders() {
        jwtDecoder = new CompositeJwtDecoder(Collections.emptyMap(), null);
    }

    @Given("1 decoder in chain")
    public void chain_has_1_decoder() {
        jwtDecoder = new CompositeJwtDecoder(Map.of("test1", jwtDecoder1), null);
    }

    @Given("2 decoders in chain")
    public void chain_has_2_decoders() {
        jwtDecoder = new CompositeJwtDecoder(Map.of("test1", jwtDecoder1, "test2", jwtDecoder2), null);
    }

    @When("token is decoded")
    public void token_is_decoded() {
        textWorld.setLastException(catchThrowable(() ->
                jwtWorld.setDecodedToken(
                        jwtDecoder.decode(jwtWorld.getToken()))));
    }

    /**
     * Ensures decoding resulted is {@link OAuth2ErrorCodes#INVALID_TOKEN} (with {@link JwtException}).
     */
    @Then("token is invalid")
    public void token_is_invalid() {
        assertThat(textWorld.getLastException())
                .as("exception")
                .isNotNull();

        assertThat(textWorld.getLastException())
                .as("exception class")
                .isInstanceOf(JwtException.class);

        // error code for blocked tokens is intentionally indistinguishable from that for expired ones
        assertThat(textWorld.getLastException().getMessage())
                .as("exception message")
                .isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    }

    /**
     * Ensures decoding succeeded.
     */
    @Then("access is granted")
    public void access_is_granted() {
        assertThat(jwtWorld.getDecodedToken())
                .as("JWT")
                .isNotNull();

        assertThat(textWorld.getLastException())
                .as("exception")
                .isNull();
    }

    /**
     * Verifies that {@link JwtDecoder#decode(String)} was called for token.
     *
     * @param ordinalNumber starts with 1, points to {@link CompositeJwtDecoder#getJwtDecoders()}
     */
    @Then("decoder #{int} was called")
    public void decoder_was_called(int ordinalNumber) {
        ArgumentCaptor<String> arg = ArgumentCaptor.forClass(String.class);
        verify(jwtDecoder.getJwtDecoders().get(ordinalNumber - 1)).decode(arg.capture());

        assertThat(arg.getValue())
                .as("decode - token")
                .isEqualTo(jwtWorld.getToken());
    }

    /**
     * Verifies that {@link JwtDecoder#decode(String)} was never called.
     *
     * @param ordinalNumber starts with 1, points to {@link CompositeJwtDecoder#getJwtDecoders()}
     */
    @Then("decoder #{int} was not called")
    public void decoder_was_not_called(int ordinalNumber) {
        verifyNoInteractions(jwtDecoder.getJwtDecoders().get(ordinalNumber - 1));
    }

    /**
     * Mocks {@link JwtDecoder#decode(String)} to return a certain dummy {@link Jwt} in all cases.
     *
     * @param ordinalNumber starts with 1, points to {@link CompositeJwtDecoder#getJwtDecoders()}
     */
    @Then("decoder #{int} accepts tokens")
    public void decoder_accepts_tokens(int ordinalNumber) {
        Jwt dummyPermissiveJwt = new Jwt(jwtWorld.getToken(),
                Instant.now(), Instant.now().plusSeconds(3600),
                Map.of("header", "value"),
                Map.of("claim", "value"));

        when(jwtDecoder.getJwtDecoders().get(ordinalNumber - 1).decode(anyString()))
                .thenReturn(dummyPermissiveJwt);
    }

    /**
     * Mocks {@link JwtDecoder#decode(String)} to fail.
     *
     * @param ordinalNumber starts with 1, points to {@link CompositeJwtDecoder#getJwtDecoders()}
     */
    @Then("decoder #{int} rejects tokens")
    public void decoder_rejects_tokens(int ordinalNumber) {
        when(jwtDecoder.getJwtDecoders().get(ordinalNumber - 1).decode(anyString()))
                .thenThrow(new JwtValidationException(OAuth2ErrorCodes.INVALID_TOKEN,
                        List.of(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN))));
    }

}
