package guru.nicks.commons.cucumber.world;

import guru.nicks.commons.auth.domain.CommonsUserPrincipal;
import guru.nicks.commons.auth.domain.JwtProvider;

import io.cucumber.spring.ScenarioScope;
import lombok.Data;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * Domain-specific state shared between scenario steps. Thanks to {@link ScenarioScope @ScenarioScope}, each scenario
 * gets a fresh copy.
 */
@Component
@ScenarioScope
@Data
public class UserPrincipalWorld {

    private String username;
    private String password;

    private Set<TestUserRole> roles;
    private Map<String, Object> attributes;

    private String id;
    private String email;
    private Boolean emailVerified;

    private JwtProvider jwtProvider;
    private String languageCode;

    private String firstName;
    private String lastName;
    private String fullName;

    private String pictureLink;

    private CommonsUserPrincipal<TestUserRole> userPrincipal;
    private CommonsUserPrincipal<TestUserRole> copiedUserPrincipal;

}
