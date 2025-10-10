package guru.nicks.cucumber.world;

import io.cucumber.spring.ScenarioScope;
import lombok.Data;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Domain-specific (not feature-specific) state shared between scenario steps. Thanks to
 * {@link ScenarioScope @ScenarioScope}, each scenario gets a fresh copy.
 */
@Component
@ScenarioScope
@Data
public class JwtWorld {

    private String token;
    private Jwt decodedToken;

}
