package guru.nicks.cucumber;

import guru.nicks.security.filter.CustomCorsFilter;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.DataTableType;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.Value;
import org.junit.platform.commons.util.StringUtils;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CustomCorsFilterSteps {

    private final CorsConfiguration corsConfiguration = new CorsConfiguration();
    private CustomCorsFilter corsFilter;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private CorsConfigurationSource configSource;
    private AutoCloseable closeableMocks;

    @Before
    public void beforeEachScenario() {
        closeableMocks = MockitoAnnotations.openMocks(this);
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();
    }

    @DataTableType
    public HeaderEntry createHeaderEntry(Map<String, String> entry) {
        return HeaderEntry.builder()
                .name(entry.get("name"))
                .value(entry.get("value"))
                .build();
    }

    @Given("a CustomCorsFilter is created with allowed origins {string}")
    public void customCorsFilterIsCreatedWithAllowedOrigins(String allowedOrigins) {
        corsConfiguration.setAllowedOrigins(parseAllowedOrigins(allowedOrigins));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("Origin", "Content-Type", "Authorization"));

        when(configSource.getCorsConfiguration(any(HttpServletRequest.class)))
                .thenReturn(corsConfiguration);

        corsFilter = new CustomCorsFilter(configSource);
    }

    @Given("the request method is {string}")
    public void theRequestMethodIs(String method) {
        when(request.getMethod())
                .thenReturn(method);
    }

    @Given("the request has the following headers:")
    public void theRequestHasTheFollowingHeaders(List<HeaderEntry> headers) {
        for (HeaderEntry header : headers) {
            when(request.getHeader(header.getName()))
                    .thenReturn(header.getValue());
        }
    }

    @When("a request is made with origin {string}")
    public void aRequestIsMadeWithOrigin(String origin) throws ServletException, IOException {
        if (StringUtils.isNotBlank(origin)) {
            when(request.getHeader(HttpHeaders.ORIGIN))
                    .thenReturn(origin);
        }

        corsFilter.doFilter(request, response, filterChain);
    }

    @When("the filter is applied")
    public void theFilterIsApplied() throws ServletException, IOException {
        corsFilter.doFilter(request, response, filterChain);
    }

    @Then("the response status should be {int}")
    public void theResponseStatusShouldBe(int status) {
        verify(response).setStatus(status);
    }

    @Then("the filter chain should not be called")
    public void theFilterChainShouldNotBeCalled() throws ServletException, IOException {
        verify(filterChain, never()).doFilter(request, response);
    }

    @Then("the filter chain should be called: {booleanValue}")
    public void theFilterChainShouldOrNotBeCalled(boolean called) throws ServletException, IOException {
        if (called) {
            verify(filterChain).doFilter(request, response);
        } else {
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Then("the response should have the {string} header")
    public void theResponseShouldHaveTheHeader(String headerName) {
        verify(response).setHeader(eq(headerName), any(String.class));
    }

    @Then("the response should have the {string} header with value {string}")
    public void theResponseShouldHaveHeaderWithValue(String headerName, String headerValue) {
        verify(response).setHeader(headerName, headerValue);
    }

    @Then("the response should have the {string} header with value {string}: {booleanValue}")
    public void theResponseShouldHaveOrNotHeaderWithValue(String headerName, String headerValue, boolean shouldHave) {
        if (shouldHave) {
            verify(response).setHeader(headerName, headerValue);
        } else {
            verify(response, never()).setHeader(eq(headerName), any());
        }
    }

    private List<String> parseAllowedOrigins(String allowedOrigins) {
        if ("*".equals(allowedOrigins)) {
            return List.of("*");
        }

        return Arrays.stream(allowedOrigins.split(","))
                .map(String::strip)
                .toList();
    }

    @Value
    @Builder
    public static class HeaderEntry {

        String name;
        String value;

    }

}
