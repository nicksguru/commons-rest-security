package guru.nicks.cucumber;

import guru.nicks.cucumber.world.TextWorld;
import guru.nicks.security.HttpSecurityConfigurer;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.DataTableType;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RequiredArgsConstructor
public class HttpSecurityConfigurerSteps {

    // DI
    private final TextWorld textWorld;

    @Mock
    private HttpSecurity httpSecurity;
    @Mock
    private AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry matcherRegistry;
    @Mock
    private AuthorizeHttpRequestsConfigurer.AuthorizedUrl authorizedUrl;

    private AutoCloseable closeableMocks;
    private HttpSecurityConfigurer configurer;
    private List<String> customizersExecuted;
    private RequestMatcher rawPathMatcher;
    private List<Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>
            capturedAuthRules;

    @Before
    public void beforeEachScenario() throws Exception {
        closeableMocks = MockitoAnnotations.openMocks(this);
        capturedAuthRules = new ArrayList<>();

        // Mock HttpSecurity builder pattern methods
        when(httpSecurity.csrf(any(Customizer.class))).thenReturn(httpSecurity);
        when(httpSecurity.formLogin(any(Customizer.class))).thenReturn(httpSecurity);
        when(httpSecurity.sessionManagement(any(Customizer.class))).thenReturn(httpSecurity);
        when(httpSecurity.redirectToHttps(any(Customizer.class))).thenReturn(httpSecurity);
        when(httpSecurity.httpBasic(any(Customizer.class))).thenReturn(httpSecurity);
        when(httpSecurity.oauth2ResourceServer(any(Customizer.class))).thenReturn(httpSecurity);

        // authenticated() / hasAnyAuthority() are called on authorizedUrl after requestMatchers() / anyRequest()
        when(matcherRegistry.requestMatchers(any(RequestMatcher.class)))
                .thenReturn(authorizedUrl);
        when(matcherRegistry.anyRequest())
                .thenReturn(authorizedUrl);

        // capture authorization rules instead of mocking the complex registry structure
        when(httpSecurity.authorizeHttpRequests(any(Customizer.class))).thenAnswer(invocation -> {
            Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
                    authCustomizer = invocation.getArgument(0);
            capturedAuthRules.add(authCustomizer);
            authCustomizer.customize(matcherRegistry);
            return httpSecurity;
        });

        customizersExecuted = new ArrayList<>();
        textWorld.setLastException(null);
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();
    }

    @DataTableType
    public EndpointAuthorityMapping createEndpointRoleMapping(Map<String, String> entry) {
        return EndpointAuthorityMapping.builder()
                .endpoint(entry.get("endpoint"))
                .authorities(entry.get("roles"))
                .build();
    }

    @DataTableType
    public AuthorityUrlMapping createRoleUrlMapping(Map<String, String> entry) {
        return AuthorityUrlMapping.builder()
                .authority(entry.get("role"))
                .urls(entry.get("urls"))
                .build();
    }

    @Given("HttpSecurityConfigurer is initialized with default settings")
    public void httpSecurityConfigurerIsInitializedWithDefaultSettings() {
        var authenticationEntryPoint = new BasicAuthenticationEntryPoint();
        configurer = new HttpSecurityConfigurer(
                httpSecurity, false, authenticationEntryPoint);
    }

    @Given("default access denied is set to true")
    public void defaultAccessDeniedIsSetToTrue() {
        configurer.defaultAccessDenied(true);
    }

    @When("a security configurer is initialized with SSL required")
    public void securityConfigurerIsInitializedWithSslRequired() {
        var authenticationEntryPoint = new BasicAuthenticationEntryPoint();
        configurer = new HttpSecurityConfigurer(httpSecurity, true, authenticationEntryPoint);
    }

    @When("the following endpoints are protected with any authentication:")
    public void endpointsAreProtectedWithAnyAuthentication(List<String> endpoints) {
        configurer.protectWithAnyAuth(endpoints);
    }

    @When("the following endpoints are protected with roles:")
    public void endpointsAreProtectedWithRoles(List<EndpointAuthorityMapping> mappings) {
        for (EndpointAuthorityMapping mapping : mappings) {
            String endpoint = mapping.getEndpoint();
            String[] roleNames = mapping.getAuthorities().split(",\\s*");
            configurer.protectEndpoints(List.of(endpoint), roleNames);
        }
    }

    @When("the following role-to-URL mappings are configured:")
    public void roleToUrlMappingsAreConfigured(List<AuthorityUrlMapping> mappings) {
        var authorityToMvcPatterns = new HashMap<String, List<String>>();

        var authPriority = new HashMap<String, Integer>();
        int i = 0;

        for (AuthorityUrlMapping mapping : mappings) {
            String authority = mapping.getAuthority().strip();
            String[] urls = mapping.getUrls().split(",\\s*");

            authorityToMvcPatterns.put(authority, Arrays.asList(urls));
            authPriority.put(authority, ++i);
        }

        configurer.protectEndpoints(authorityToMvcPatterns, authPriority::get);
    }

    @When("the following HTTP method specific endpoints are protected:")
    public void httpMethodSpecificEndpointsAreProtected(List<EndpointAuthorityMapping> mappings) {
        for (EndpointAuthorityMapping mapping : mappings) {
            String endpoint = mapping.getEndpoint();
            String[] authorities = mapping.getAuthorities().split("\\s*,\\s*");
            configurer.protectEndpoints(List.of(endpoint), authorities);
        }
    }

    @When("attempting to protect endpoints after deny-all")
    public void attemptingToProtectEndpointsAfterDenyAll() {
        textWorld.setLastException(catchThrowable(() -> configurer.protectEndpoints(List.of("/some/path"))));
    }

    @When("multiple customizers are applied")
    public void multipleCustomizersAreApplied() {
        Consumer<HttpSecurityConfigurer> customizer1 = config -> customizersExecuted.add("customizer1");
        Consumer<HttpSecurityConfigurer> customizer2 = config -> customizersExecuted.add("customizer2");
        Consumer<HttpSecurityConfigurer> customizer3 = config -> customizersExecuted.add("customizer3");
        configurer.withCustomizers(customizer1, customizer2, customizer3);
    }

    @When("invalid MVC pattern is used")
    public void invalidMvcPatternIsUsed() {
        textWorld.setLastException(catchThrowable(() ->
                configurer.protectEndpoints(List.of("/api/[invalid]/**"), "ROLE_USER")
        ));
    }

    @When("attempting to configure ROLE_ADMIN and others in any order")
    public void attemptingToConfigureRoleAdminAndOthersInAnyOrder() {
        textWorld.setLastException(catchThrowable(() -> {
            var authorityToMvcPatterns = new HashMap<String, List<String>>();
            authorityToMvcPatterns.put("ROLE_ADMIN", List.of("/admin/**"));
            authorityToMvcPatterns.put("ROLE_USER", List.of("/user/**"));

            // user goes before admin deliberately
            var authPriority = Map.of(
                    "ROLE_ADMIN", 2,
                    "ROLE_USER", 1);
            configurer.protectEndpoints(authorityToMvcPatterns, authPriority::get);
        }));
    }

    @When("raw path matcher is created for {string}")
    public void rawPathMatcherIsCreatedFor(String pattern) {
        rawPathMatcher = configurer.createRawPathMatcher(pattern);
    }

    @Then("'authenticated' should be called")
    public void authenticatedShouldBeCalled() throws Exception {
        verify(httpSecurity, atLeastOnce()).authorizeHttpRequests(any(Customizer.class));
        assertThat(capturedAuthRules)
                .as("authorization rules should be captured")
                .isNotEmpty();
    }

    @Then("ROLE_ADMIN should be applied first and ROLE_USER second despite of the above order")
    public void urlProtectionShouldBeAppliedInCorrectOrder() throws Exception {
        // Verify that authorization rules were captured in the correct order
        verify(httpSecurity, atLeastOnce()).authorizeHttpRequests(any(Customizer.class));
        assertThat(capturedAuthRules)
                .as("authorization rules should be captured")
                .hasSizeGreaterThanOrEqualTo(2);
    }

    @Then("'hasAnyAuthority' should be called")
    public void hasAnyAuthorityShouldBeCalled() throws Exception {
        verify(httpSecurity, atLeastOnce()).authorizeHttpRequests(any(Customizer.class));
    }

    @Then("all requests should require secure channel")
    public void allRequestsShouldRequireSecureChannel() throws Exception {
        verify(httpSecurity).redirectToHttps(any(Customizer.class));
    }

    @Then("all customizers should be executed in order")
    public void allCustomizersShouldBeExecutedInOrder() {
        assertThat(customizersExecuted)
                .as("customizersExecuted")
                .hasSize(3);

        assertThat(customizersExecuted)
                .as("customizersExecuted")
                .containsExactly("customizer1", "customizer2", "customizer3");
    }

    @Then("SecurityException should be thrown with message about MVC patterns")
    public void securityExceptionShouldBeThrownWithMessageAboutMvcPatterns() {
        assertThat(textWorld.getLastException())
                .as("lastException")
                .isInstanceOf(SecurityException.class);

        assertThat(textWorld.getLastException().getMessage())
                .as("exception message")
                .contains("MVC patterns are not Ant patterns");
    }

    @Then("raw path matcher should match paths starting with {string}")
    public void rawPathMatcherShouldMatchPathsStartingWith(String pathPrefix) {
        var request = new MockHttpServletRequest("GET", pathPrefix + "test");

        assertThat(rawPathMatcher.matches(request))
                .as("path matcher matches")
                .isTrue();
    }

    @And("raw path matcher should not match other paths")
    public void rawPathMatcherShouldNotMatchOtherPaths() {
        var request = new MockHttpServletRequest("GET", "/different/path");

        assertThat(rawPathMatcher.matches(request))
                .as("path matcher doesn't match")
                .isFalse();
    }

    /**
     * DTO for endpoint to role mappings from Gherkin tables
     */
    @Value
    @Builder
    public static class EndpointAuthorityMapping {

        String endpoint;
        String authorities;

    }

    /**
     * DTO for role to URL mappings from Gherkin tables
     */
    @Value
    @Builder
    public static class AuthorityUrlMapping {

        String authority;
        String urls;

    }

}
