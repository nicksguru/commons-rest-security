package guru.nicks.commons.cucumber;

import guru.nicks.commons.log.domain.LogContext;
import guru.nicks.commons.rest.RequestSummaryLogger;
import guru.nicks.commons.utils.DurationStatistics;
import guru.nicks.commons.utils.HttpRequestUtils;
import guru.nicks.commons.utils.JvmUtils;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.servlet.http.HttpServletResponse;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.util.unit.DataSize;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RequestSummaryLoggerSteps {

    @Spy
    private final DurationStatistics requestSummaryAccumulator = new DurationStatistics(100, Duration.ofSeconds(1));
    @Mock
    private HttpServletResponse httpServletResponse;
    private AutoCloseable closeableMocks;

    private RequestSummaryLogger requestSummaryLogger;
    private String requestUri;
    private Duration requestDuration;

    private ListAppender<ILoggingEvent> logAppender;
    private MockedStatic<JvmUtils> jvmUtilsMock;
    private MockedStatic<HttpRequestUtils> httpRequestUtilsMock;

    @Before
    public void beforeEachScenario() {
        closeableMocks = MockitoAnnotations.openMocks(this);
        setupLogAppender();
        setupStaticMocks();
        MDC.clear();
    }

    @After
    public void afterEachScenario() throws Exception {
        closeableMocks.close();

        if (logAppender != null) {
            logAppender.stop();
        }

        if (jvmUtilsMock != null) {
            jvmUtilsMock.close();
        }

        if (httpRequestUtilsMock != null) {
            httpRequestUtilsMock.close();
        }

        MDC.clear();
    }

    @Given("request statistics are configured with slow threshold of {int} milliseconds")
    public void requestStatisticsAreConfiguredWithSlowThresholdOfMilliseconds(int thresholdMs) {
        requestSummaryLogger = new RequestSummaryLogger(requestSummaryAccumulator, Duration.ofMillis(thresholdMs));
    }

    @Given("request statistics are configured with no slow threshold")
    public void requestStatisticsAreConfiguredWithNoSlowThreshold() {
        requestSummaryLogger = new RequestSummaryLogger(requestSummaryAccumulator, null);
    }

    @Given("a request URI {string}")
    public void aRequestUri(String uri) {
        requestUri = uri;
    }

    @Given("a null request URI")
    public void aNullRequestUri() {
        requestUri = null;
    }

    @Given("an HTTP response with status code {int}")
    public void anHttpResponseWithStatusCode(int statusCode) {
        when(httpServletResponse.getStatus())
                .thenReturn(statusCode);
    }

    @Given("a request duration of {int} milliseconds")
    public void aRequestDurationOfMilliseconds(int durationMs) {
        requestDuration = Duration.ofMillis(durationMs);
    }

    @Given("a trace ID {string} is present")
    public void aTraceIdIsPresent(String traceId) {
        LogContext.TRACE_ID.put(traceId);
    }

    @When("the request summary logger processes the request")
    public void theRequestSummaryLoggerProcessesTheRequest() {
        doReturn("5ms average after 10 calls during past 1 hour")
                .when(requestSummaryAccumulator)
                .accumulateMillis(
                        any(),      // not anyString() because requestUri may be null
                        anyLong()   // request duration
                );

        requestSummaryLogger.accept(requestUri, httpServletResponse, requestDuration);
    }

    @When("the request summary logger processes the request multiple times")
    public void theRequestSummaryLoggerProcessesTheRequestMultipleTimes() {
        doReturn("5ms average after 10 calls during past 1 hour")
                .when(requestSummaryAccumulator)
                .accumulateMillis(
                        any(),      // not anyString() because requestUri may be null
                        anyLong()   // request duration
                );

        // process the same request multiple times
        requestSummaryLogger.accept(requestUri, httpServletResponse, requestDuration);
        requestSummaryLogger.accept(requestUri, httpServletResponse, requestDuration);
        requestSummaryLogger.accept(requestUri, httpServletResponse, requestDuration);
    }

    @Then("the response should contain trace ID header with value {string}")
    public void theResponseShouldContainTraceIdHeaderWithValue(String expectedTraceId) {
        verify(httpServletResponse)
                .setHeader(LogContext.RESPONSE_TRACE_ID_HEADER, expectedTraceId);
    }

    @Then("the response should contain elapsed time header with value {string}")
    public void theResponseShouldContainElapsedTimeHeaderWithValue(String expectedDuration) {
        verify(httpServletResponse)
                .setHeader(LogContext.RESPONSE_MS_ELAPSED_HEADER, expectedDuration);
    }

    @Then("the log context should contain response status {string}")
    public void theLogContextShouldContainResponseStatus(String expectedStatus) {
        assertThat(LogContext.RESPONSE_HTTP_STATUS.find())
                .as("response status in log context")
                .isPresent()
                .hasValue(expectedStatus);
    }

    @Then("the log context should contain elapsed time {string}")
    public void theLogContextShouldContainElapsedTime(String expectedElapsedTime) {
        assertThat(LogContext.RESPONSE_MS_ELAPSED.find())
                .as("elapsed time in log context")
                .isPresent()
                .hasValue(expectedElapsedTime);
    }

    @Then("the log context should contain RAM free MB")
    public void theLogContextShouldContainRamFreeMb() {
        assertThat(LogContext.RAM_FREE_MB.find())
                .as("RAM free MB in log context")
                .isPresent();
    }

    @Then("the log context should contain RAM max MB")
    public void theLogContextShouldContainRamMaxMb() {
        assertThat(LogContext.RAM_MAX_MB.find())
                .as("RAM max MB in log context")
                .isPresent();
    }

    @Then("the request should be logged at {string} level")
    public void theRequestShouldBeLoggedAtLevel(String expectedLevel) {
        var logEvents = logAppender.list;

        assertThat(logEvents)
                .as("log events")
                .isNotEmpty();

        var lastLogEvent = logEvents.getLast();

        assertThat(lastLogEvent.getLevel())
                .as("log level")
                .isEqualTo(Level.valueOf(expectedLevel));
    }

    @Then("the log message should contain slow marker: {booleanValue}")
    public void theLogMessageShouldContainSlowMarker(boolean shouldContainSlowMarker) {
        var logEvents = logAppender.list;

        assertThat(logEvents)
                .as("log events")
                .isNotEmpty();

        var lastLogEvent = logEvents.getLast();
        var logMessage = lastLogEvent.getFormattedMessage();

        if (shouldContainSlowMarker) {
            assertThat(logMessage)
                    .as("log message with slow marker")
                    .contains("[SLOW]");
        } else {
            assertThat(logMessage)
                    .as("log message without slow marker")
                    .doesNotContain("[SLOW]");
        }
    }

    @Then("the log message should contain status code {string}")
    public void theLogMessageShouldContainStatusCode(String expectedStatusCode) {
        var logEvents = logAppender.list;

        assertThat(logEvents)
                .as("log events")
                .isNotEmpty();

        var lastLogEvent = logEvents.getLast();

        assertThat(lastLogEvent.getFormattedMessage())
                .as("log message with status code")
                .contains(expectedStatusCode);
    }

    @Then("the same logger should be returned for identical parameters")
    public void theSameLoggerShouldBeReturnedForIdenticalParameters() {
        var logEvents = logAppender.list;

        assertThat(logEvents)
                .as("log events")
                .hasSizeGreaterThan(1);

        // all log events should have the same level since parameters are identical
        var firstLogLevel = logEvents.getFirst().getLevel();

        assertThat(logEvents)
                .as("all log events should have same level")
                .allMatch(event -> event.getLevel().equals(firstLogLevel));
    }

    /**
     * Sets up log appender to capture log events for verification.
     */
    private void setupLogAppender() {
        var logger = (Logger) LoggerFactory.getLogger(RequestSummaryLogger.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
    }

    /**
     * Sets up static mocks for utility classes.
     */
    private void setupStaticMocks() {
        jvmUtilsMock = mockStatic(JvmUtils.class);
        jvmUtilsMock.when(JvmUtils::getMaxMemory)
                .thenReturn(DataSize.ofMegabytes(1024L));
        jvmUtilsMock.when(JvmUtils::getFreeMemory)
                .thenReturn(DataSize.ofMegabytes(512L));

        // COMMENTED OUT because conflicts for other tests calling REAL static HttpRequestUtils method - makes methods
        // other than defined here empty
        //        httpRequestUtilsMock = mockStatic(HttpRequestUtils.class);
        //        httpRequestUtilsMock.when(() -> HttpRequestUtils.resolveHttpStatus(anyInt()))
        //                .thenReturn(Optional.empty());
    }

}
