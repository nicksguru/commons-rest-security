package guru.nicks.commons.cucumber;

import guru.nicks.commons.ApplicationContextHolder;
import guru.nicks.commons.cucumber.world.TextWorld;
import guru.nicks.commons.log.domain.LogContext;
import guru.nicks.commons.security.filter.LogContextFilter;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.MDC;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Step definitions for testing {@link LogContextFilter}.
 */
@RequiredArgsConstructor
public class LogContextFilterSteps {

    // DI
    private final TextWorld textWorld;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private Environment environment;
    @Mock
    private Principal principal;
    @Mock
    private Authentication authentication;
    @Mock
    private AbstractAuthenticationToken authenticationToken;
    private AutoCloseable closeableMocks;

    private LogContextFilter logContextFilter;

    @Before
    public void beforeEachScenario() {
        closeableMocks = MockitoAnnotations.openMocks(this);

        MDC.clear();
        logContextFilter = new LogContextFilter();
        ApplicationContextHolder.setApplicationContext(applicationContext);

        // mock Environment (Spring profile etc.)
        when(applicationContext.getEnvironment())
                .thenReturn(environment);
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();
        MDC.clear();
    }

    @Given("an HTTP request with URI {string} and method {string}")
    public void anHTTPRequestWithURIAndMethod(String uri, String method) {
        when(request.getRequestURI())
                .thenReturn(uri);
        when(request.getMethod())
                .thenReturn(method);
    }

    @Given("a remote IP {string}")
    public void aRemoteIP(String ip) {
        when(request.getHeader("X-Real-IP"))
                .thenReturn(ip);
    }

    @Given("an application name {string}")
    public void anApplicationName(String appName) {
        when(environment.getProperty(ApplicationContextHolder.SPRING_APPLICATION_NAME_PROPERTY))
                .thenReturn(appName);
    }

    @Given("a Principal with name {string}")
    public void aPrincipalWithName(String name) {
        when(principal.getName())
                .thenReturn(name);
        when(request.getUserPrincipal())
                .thenReturn(principal);
    }

    @Given("an Authentication with name {string} and principal object")
    public void anAuthenticationWithNameAndPrincipalObject(String name) {
        Object customPrincipal = new Object(); // Custom principal object

        when(authentication.getName())
                .thenReturn(name);
        when(authentication.getPrincipal())
                .thenReturn(customPrincipal);
        when(request.getUserPrincipal())
                .thenReturn(authentication);
    }

    @Given("an AbstractAuthenticationToken with subject {string}")
    public void anAbstractAuthenticationTokenWithSubject(String subject) {
        Map<String, Object> details = new HashMap<>();
        details.put("sub", subject);

        when(authenticationToken.getName())
                .thenReturn("token-user");
        when(authenticationToken.getDetails())
                .thenReturn(details);
        // filter notices the token is Authentication and calls getPrincipal() on it
        when(authenticationToken.getPrincipal())
                .thenReturn(authenticationToken);
        when(request.getUserPrincipal())
                .thenReturn(authenticationToken);
    }

    @When("the LogContextFilter processes the request")
    public void theLogContextFilterProcessesTheRequest() {
        LogContextFilter.storeRequestParametersInMdc(request);
    }

    @When("the LogContextFilter's doFilterInternal method is called")
    public void theLogContextFilterSDoFilterInternalMethodIsCalled() {
        try {
            logContextFilter.doFilter(request, response, filterChain);
        } catch (ServletException | IOException e) {
            textWorld.setLastException(e);
        }
    }

    @Then("the MDC should contain {word} with value {string}")
    public void theMDCShouldContainWithValue(String contextName, String expectedValue) {
        LogContext logContext = LogContext.valueOf(contextName);
        assertThat(logContext.find())
                .as(contextName)
                .isPresent()
                .hasValue(expectedValue);
    }

    @Then("the MDC should not contain {word}")
    public void theMDCShouldNotContain(String contextName) {
        LogContext logContext = LogContext.valueOf(contextName);
        assertThat(logContext.find())
                .as(contextName)
                .isEmpty();
    }

    @Then("the filter chain's doFilter method should be called")
    public void theFilterChainSDoFilterMethodShouldBeCalled() {
        try {
            verify(filterChain).doFilter(request, response);
        } catch (ServletException | IOException e) {
            textWorld.setLastException(e);
        }
    }

}
