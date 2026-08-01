package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.domain.CommonsUserPrincipal;
import guru.nicks.commons.auth.domain.JwtProvider;
import guru.nicks.commons.cucumber.world.TestUserRole;
import guru.nicks.commons.cucumber.world.UserPrincipalWorld;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Step definitions for {@link CommonsUserPrincipal}.
 */
@RequiredArgsConstructor
public class CommonsUserPrincipalSteps {

    // DI
    private final UserPrincipalWorld userPrincipalWorld;

    @Given("a username {string}")
    public void aUsername(String username) {
        userPrincipalWorld.setUsername(username);
    }

    @Given("a password {string}")
    public void aPassword(String password) {
        userPrincipalWorld.setPassword("null".equals(password) ? null : password);
    }

    @Given("roles:")
    public void roles(List<String> roles) {
        userPrincipalWorld.setRoles(roles.stream()
                .map(TestUserRole::valueOf)
                .collect(Collectors.toCollection(TreeSet::new)));
    }

    @Given("no roles")
    public void noRoles() {
        userPrincipalWorld.setRoles(null);
    }

    @Given("attributes:")
    public void attributes(Map<String, String> attributes) {
        userPrincipalWorld.setAttributes(new LinkedHashMap<>(attributes));
    }

    @Given("no attributes")
    public void noAttributes() {
        userPrincipalWorld.setAttributes(null);
    }

    @Given("user ID {string}")
    public void userId(String id) {
        userPrincipalWorld.setId(id);
    }

    @Given("email {string}")
    public void email(String email) {
        userPrincipalWorld.setEmail(email);
    }

    @Given("email verified is {booleanValue}")
    public void emailVerifiedIs(boolean emailVerified) {
        userPrincipalWorld.setEmailVerified(emailVerified);
    }

    @Given("JWT provider is {word}")
    public void jwtProviderIs(String jwtProvider) {
        userPrincipalWorld.setJwtProvider("null".equals(jwtProvider)
                ? null
                : JwtProvider.valueOf(jwtProvider));
    }

    @Given("language code {string}")
    public void languageCode(String languageCode) {
        userPrincipalWorld.setLanguageCode("null".equals(languageCode)
                ? null
                : languageCode);
    }

    @Given("first name {string}")
    public void firstName(String firstName) {
        userPrincipalWorld.setFirstName("null".equals(firstName)
                ? null
                : firstName);
    }

    @Given("last name {string}")
    public void lastName(String lastName) {
        userPrincipalWorld.setLastName("null".equals(lastName)
                ? null
                : lastName);
    }

    @Given("full name {string}")
    public void fullName(String fullName) {
        userPrincipalWorld.setFullName("null".equals(fullName)
                ? null
                : fullName);
    }

    @Given("picture link {string}")
    public void pictureLink(String pictureLink) {
        userPrincipalWorld.setPictureLink("null".equals(pictureLink)
                ? null
                : pictureLink);
    }

    @Given("a password null")
    public void aPasswordNull() {
        userPrincipalWorld.setPassword(null);
    }

    @Given("language code null")
    public void languageCodeNull() {
        userPrincipalWorld.setLanguageCode(null);
    }

    @Given("first name null")
    public void firstNameNull() {
        userPrincipalWorld.setFirstName(null);
    }

    @Given("last name null")
    public void lastNameNull() {
        userPrincipalWorld.setLastName(null);
    }

    @Given("full name null")
    public void fullNameNull() {
        userPrincipalWorld.setFullName(null);
    }

    @Given("picture link null")
    public void pictureLinkNull() {
        userPrincipalWorld.setPictureLink(null);
    }

    @When("a user principal is created")
    public void aUserPrincipalIsCreated() {
        userPrincipalWorld.setUserPrincipal(CommonsUserPrincipal.<TestUserRole>builder()
                .username(userPrincipalWorld.getUsername())
                .password(userPrincipalWorld.getPassword())
                .roles(userPrincipalWorld.getRoles())
                .attributes(userPrincipalWorld.getAttributes())
                .id(userPrincipalWorld.getId())
                .email(userPrincipalWorld.getEmail())
                .emailVerified(userPrincipalWorld.getEmailVerified())
                .jwtProvider(userPrincipalWorld.getJwtProvider())
                .languageCode(userPrincipalWorld.getLanguageCode())
                .firstName(userPrincipalWorld.getFirstName())
                .lastName(userPrincipalWorld.getLastName())
                .fullName(userPrincipalWorld.getFullName())
                .pictureLink(userPrincipalWorld.getPictureLink())
                .build());
    }

    @When("a copy is made using the copy constructor")
    public void aCopyIsMadeUsingTheCopyConstructor() {
        var copy = (CommonsUserPrincipal<TestUserRole>) userPrincipalWorld.getUserPrincipal().toBuilder().build();
        userPrincipalWorld.setCopiedUserPrincipal(copy);
    }

    @Then("the user principal username should be {string}")
    public void theUserPrincipalUsernameShouldBe(String username) {
        assertThat(userPrincipalWorld.getUserPrincipal().getUsername())
                .as("user principal username")
                .isEqualTo(username);
    }

    @Then("the user principal password should be {string}")
    public void theUserPrincipalPasswordShouldBe(String password) {
        assertThat(userPrincipalWorld.getUserPrincipal().getPassword())
                .as("user principal password")
                .isEqualTo("empty".equals(password) ? "" : password);
    }

    @Then("the user principal password should be empty")
    public void theUserPrincipalPasswordShouldBeEmpty() {
        assertThat(userPrincipalWorld.getUserPrincipal().getPassword())
                .as("user principal password")
                .isEmpty();
    }

    @Then("the user principal roles should be:")
    public void theUserPrincipalRolesShouldBe(List<String> expectedRoles) {
        assertThat(userPrincipalWorld.getUserPrincipal().getRoles())
                .as("user principal roles")
                .isEqualTo(expectedRoles.stream()
                        .map(TestUserRole::valueOf)
                        .collect(Collectors.toCollection(TreeSet::new)));
    }

    @Then("the user principal roles should be null")
    public void theUserPrincipalRolesShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getRoles())
                .as("user principal roles")
                .isNull();
    }

    @Then("the user principal attributes should be:")
    public void theUserPrincipalAttributesShouldBe(Map<String, String> expectedAttributes) {
        assertThat(userPrincipalWorld.getUserPrincipal().getAttributes())
                .as("user principal attributes")
                .isEqualTo(new LinkedHashMap<>(expectedAttributes));
    }

    @Then("the user principal attributes should be null")
    public void theUserPrincipalAttributesShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getAttributes())
                .as("user principal attributes")
                .isNull();
    }

    @Then("the user principal ID should be {string}")
    public void theUserPrincipalIdShouldBe(String id) {
        assertThat(userPrincipalWorld.getUserPrincipal().getId())
                .as("user principal ID")
                .isEqualTo(id);
    }

    @Then("the user principal email should be {string}")
    public void theUserPrincipalEmailShouldBe(String email) {
        assertThat(userPrincipalWorld.getUserPrincipal().getEmail())
                .as("user principal email")
                .isEqualTo(email);
    }

    @Then("the user principal email verified should be {booleanValue}")
    public void theUserPrincipalEmailVerifiedShouldBe(boolean emailVerified) {
        assertThat(userPrincipalWorld.getUserPrincipal().isEmailVerified())
                .as("user principal email verified")
                .isEqualTo(emailVerified);
    }

    @Then("the user principal JWT provider should be {word}")
    public void theUserPrincipalJwtProviderShouldBe(String jwtProvider) {
        if ("null".equals(jwtProvider)) {
            assertThat(userPrincipalWorld.getUserPrincipal().getJwtProvider())
                    .as("user principal JWT provider")
                    .isNull();
        } else {
            assertThat(userPrincipalWorld.getUserPrincipal().getJwtProvider())
                    .as("user principal JWT provider")
                    .isEqualTo(JwtProvider.valueOf(jwtProvider));
        }
    }

    @Then("the user principal language code should be {string}")
    public void theUserPrincipalLanguageCodeShouldBe(String languageCode) {
        assertThat(userPrincipalWorld.getUserPrincipal().getLanguageCode())
                .as("user principal language code")
                .isEqualTo("null".equals(languageCode) ? null : languageCode);
    }

    @Then("the user principal first name should be {string}")
    public void theUserPrincipalFirstNameShouldBe(String firstName) {
        assertThat(userPrincipalWorld.getUserPrincipal().getFirstName())
                .as("user principal first name")
                .isEqualTo("null".equals(firstName) ? null : firstName);
    }

    @Then("the user principal last name should be {string}")
    public void theUserPrincipalLastNameShouldBe(String lastName) {
        assertThat(userPrincipalWorld.getUserPrincipal().getLastName())
                .as("user principal last name")
                .isEqualTo("null".equals(lastName) ? null : lastName);
    }

    @Then("the user principal full name should be {string}")
    public void theUserPrincipalFullNameShouldBe(String fullName) {
        assertThat(userPrincipalWorld.getUserPrincipal().getFullName())
                .as("user principal full name")
                .isEqualTo("null".equals(fullName) ? null : fullName);
    }

    @Then("the user principal picture link should be {string}")
    public void theUserPrincipalPictureLinkShouldBe(String pictureLink) {
        assertThat(userPrincipalWorld.getUserPrincipal().getPictureLink())
                .as("user principal picture link")
                .isEqualTo("null".equals(pictureLink) ? null : pictureLink);
    }

    @Then("the user principal language code should be null")
    public void theUserPrincipalLanguageCodeShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getLanguageCode())
                .as("user principal language code")
                .isNull();
    }

    @Then("the user principal first name should be null")
    public void theUserPrincipalFirstNameShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getFirstName())
                .as("user principal first name")
                .isNull();
    }

    @Then("the user principal last name should be null")
    public void theUserPrincipalLastNameShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getLastName())
                .as("user principal last name")
                .isNull();
    }

    @Then("the user principal full name should be null")
    public void theUserPrincipalFullNameShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getFullName())
                .as("user principal full name")
                .isNull();
    }

    @Then("the user principal picture link should be null")
    public void theUserPrincipalPictureLinkShouldBeNull() {
        assertThat(userPrincipalWorld.getUserPrincipal().getPictureLink())
                .as("user principal picture link")
                .isNull();
    }

    @Then("the user principal should be a foreign JWT")
    public void theUserPrincipalShouldBeAForeignJwt() {
        assertThat(userPrincipalWorld.getUserPrincipal().isForeignJwt())
                .as("user principal is foreign JWT")
                .isTrue();
    }

    @Then("the user principal should not be a foreign JWT")
    public void theUserPrincipalShouldNotBeAForeignJwt() {
        assertThat(userPrincipalWorld.getUserPrincipal().isForeignJwt())
                .as("user principal is foreign JWT")
                .isFalse();
    }

    @Then("the copied user principal username should be {string}")
    public void theCopiedUserPrincipalUsernameShouldBe(String username) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getUsername())
                .as("copied user principal username")
                .isEqualTo(username);
    }

    @Then("the copied user principal password should be {string}")
    public void theCopiedUserPrincipalPasswordShouldBe(String password) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getPassword())
                .as("copied user principal password")
                .isEqualTo(password);
    }

    @Then("the copied user principal roles should be:")
    public void theCopiedUserPrincipalRolesShouldBe(List<String> expectedRoles) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getRoles())
                .as("copied user principal roles")
                .isEqualTo(expectedRoles.stream()
                        .map(TestUserRole::valueOf)
                        .collect(Collectors.toCollection(TreeSet::new)));
    }

    @Then("the copied user principal attributes should be:")
    public void theCopiedUserPrincipalAttributesShouldBe(Map<String, String> expectedAttributes) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getAttributes())
                .as("copied user principal attributes")
                .isEqualTo(new LinkedHashMap<>(expectedAttributes));
    }

    @Then("the copied user principal ID should be {string}")
    public void theCopiedUserPrincipalIdShouldBe(String id) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getId())
                .as("copied user principal ID")
                .isEqualTo(id);
    }

    @Then("the copied user principal email should be {string}")
    public void theCopiedUserPrincipalEmailShouldBe(String email) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getEmail())
                .as("copied user principal email")
                .isEqualTo(email);
    }

    @Then("the copied user principal email verified should be {booleanValue}")
    public void theCopiedUserPrincipalEmailVerifiedShouldBe(boolean emailVerified) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().isEmailVerified())
                .as("copied user principal email verified")
                .isEqualTo(emailVerified);
    }

    @Then("the copied user principal JWT provider should be {word}")
    public void theCopiedUserPrincipalJwtProviderShouldBe(String jwtProvider) {
        if ("null".equals(jwtProvider)) {
            assertThat(userPrincipalWorld.getCopiedUserPrincipal().getJwtProvider())
                    .as("copied user principal JWT provider")
                    .isNull();
        } else {
            assertThat(userPrincipalWorld.getCopiedUserPrincipal().getJwtProvider())
                    .as("copied user principal JWT provider")
                    .isEqualTo(JwtProvider.valueOf(jwtProvider));
        }
    }

    @Then("the copied user principal language code should be {string}")
    public void theCopiedUserPrincipalLanguageCodeShouldBe(String languageCode) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getLanguageCode())
                .as("copied user principal language code")
                .isEqualTo("null".equals(languageCode) ? null : languageCode);
    }

    @Then("the copied user principal first name should be {string}")
    public void theCopiedUserPrincipalFirstNameShouldBe(String firstName) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getFirstName())
                .as("copied user principal first name")
                .isEqualTo("null".equals(firstName) ? null : firstName);
    }

    @Then("the copied user principal last name should be {string}")
    public void theCopiedUserPrincipalLastNameShouldBe(String lastName) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getLastName())
                .as("copied user principal last name")
                .isEqualTo("null".equals(lastName) ? null : lastName);
    }

    @Then("the copied user principal full name should be {string}")
    public void theCopiedUserPrincipalFullNameShouldBe(String fullName) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getFullName())
                .as("copied user principal full name")
                .isEqualTo("null".equals(fullName) ? null : fullName);
    }

    @Then("the copied user principal picture link should be {string}")
    public void theCopiedUserPrincipalPictureLinkShouldBe(String pictureLink) {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().getPictureLink())
                .as("copied user principal picture link")
                .isEqualTo("null".equals(pictureLink) ? null : pictureLink);
    }

    @Then("the copied user principal should be a foreign JWT")
    public void theCopiedUserPrincipalShouldBeAForeignJwt() {
        assertThat(userPrincipalWorld.getCopiedUserPrincipal().isForeignJwt())
                .as("copied user principal is foreign JWT")
                .isTrue();
    }

    @Then("the user principal name should be {string}")
    public void theUserPrincipalNameShouldBe(String name) {
        assertThat(userPrincipalWorld.getUserPrincipal().getName())
                .as("user principal name")
                .isEqualTo(name);
    }

    @Then("the user principal authorities should be:")
    public void theUserPrincipalAuthoritiesShouldBe(List<String> expectedAuthorities) {
        var authorities = userPrincipalWorld.getUserPrincipal().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        assertThat(authorities)
                .as("user principal authorities")
                .containsExactlyElementsOf(expectedAuthorities);
    }

    @Then("the user principal should have authority {string}")
    public void theUserPrincipalShouldHaveAuthority(String authority) {
        assertThat(userPrincipalWorld.getUserPrincipal().getAuthorities())
                .as("user principal has authority " + authority)
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(authority));
    }

    @Then("the user principal should not have authority {string}")
    public void theUserPrincipalShouldNotHaveAuthority(String authority) {
        assertThat(userPrincipalWorld.getUserPrincipal().getAuthorities())
                .as("user principal does not have authority " + authority)
                .noneMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(authority));
    }

    @Then("the user principal roles should be immutable")
    public void theUserPrincipalRolesShouldBeImmutable() {
        var roles = userPrincipalWorld.getUserPrincipal().getRoles();

        assertThatThrownBy(() -> roles.add(TestUserRole.ROLE_USER))
                .as("roles should be immutable")
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Then("the user principal attributes should be immutable")
    public void theUserPrincipalAttributesShouldBeImmutable() {
        var attributes = userPrincipalWorld.getUserPrincipal().getAttributes();

        assertThatThrownBy(() -> attributes.put("new_key", "new_value"))
                .as("attributes should be immutable")
                .isInstanceOf(UnsupportedOperationException.class);
    }

}
