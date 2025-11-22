package guru.nicks.commons.cucumber;

import guru.nicks.commons.rest.RequestSummaryLogger;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.Builder;
import lombok.Value;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

public class LoggerDetectorSteps {

    private int httpStatusCode;
    private boolean requestIsSlow;

    private Consumer<String> detectedLogger;
    private Consumer<String> secondDetectedLogger;

    private ListAppender<ILoggingEvent> logAppender;

    @Before
    public void beforeEachScenario() {
        setupLogAppender();
    }

    @After
    public void afterEachScenario() {
        if (logAppender != null) {
            logAppender.stop();
        }
    }

    @Given("an HTTP status code of {int}")
    public void anHttpStatusCodeOf(int statusCode) {
        httpStatusCode = statusCode;
    }

    @Given("the request is slow: {booleanValue}")
    public void theRequestIsSlow(boolean isSlow) {
        requestIsSlow = isSlow;
    }

    @When("the logger detector determines the appropriate logger")
    public void theLoggerDetectorDeterminesTheAppropriateLogger() throws Exception {
        detectedLogger = invokeLoggerDetectorDetect(httpStatusCode, requestIsSlow);
    }

    @When("the logger detector determines the appropriate logger multiple times")
    public void theLoggerDetectorDeterminesTheAppropriateLoggerMultipleTimes() throws Exception {
        detectedLogger = invokeLoggerDetectorDetect(httpStatusCode, requestIsSlow);
        secondDetectedLogger = invokeLoggerDetectorDetect(httpStatusCode, requestIsSlow);
    }

    @Then("the detected logger should be at {string} level")
    public void theDetectedLoggerShouldBeAtLevel(String expectedLevel) {
        var testMessage = "Test log message";
        detectedLogger.accept(testMessage);

        var logEvents = logAppender.list;

        assertThat(logEvents)
                .as("log events")
                .isNotEmpty();

        var lastLogEvent = logEvents.getLast();

        assertThat(lastLogEvent.getLevel())
                .as("detected logger level")
                .isEqualTo(Level.valueOf(expectedLevel));

        assertThat(lastLogEvent.getFormattedMessage())
                .as("log message")
                .isEqualTo(testMessage);
    }

    @Then("the same logger instance should be returned each time")
    public void theSameLoggerInstanceShouldBeReturnedEachTime() {
        assertThat(detectedLogger)
                .as("first detected logger")
                .isSameAs(secondDetectedLogger);
    }

    @Then("the cache key should be calculated correctly")
    public void theCacheKeyShouldBeCalculatedCorrectly() throws Exception {
        // invoke again to ensure cache is used
        var cachedLogger = invokeLoggerDetectorDetect(httpStatusCode, requestIsSlow);

        assertThat(cachedLogger)
                .as("cached logger")
                .isSameAs(detectedLogger);
    }

    @Then("the cache should store the result")
    public void theCacheShouldStoreTheResult() throws Exception {
        // verify that multiple calls return the same instance (indicating caching)
        var thirdDetectedLogger = invokeLoggerDetectorDetect(httpStatusCode, requestIsSlow);

        assertThat(detectedLogger)
                .as("cached logger instance")
                .isSameAs(thirdDetectedLogger);
    }

    /**
     * Creates {@link StatusSlownessData} from DataTable map.
     *
     * @param map DataTable row as map
     * @return status slowness data
     */
    public StatusSlownessData createStatusSlownessData(Map<String, String> map) {
        return StatusSlownessData.builder()
                .statusCode(Integer.parseInt(map.get("statusCode")))
                .isSlow(Boolean.parseBoolean(map.get("isSlow")))
                .build();
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
     * Invokes the private static LoggerDetector#detect method using reflection.
     *
     * @param statusCode HTTP status code
     * @param isSlow     whether request is slow
     * @return detected logger consumer
     * @throws Exception if reflection fails
     */
    private Consumer<String> invokeLoggerDetectorDetect(int statusCode, boolean isSlow) throws Exception {
        var loggerDetectorClass = RequestSummaryLogger.LoggerDetector.class;
        Method detectMethod = loggerDetectorClass.getDeclaredMethod("detect", int.class, boolean.class);
        detectMethod.setAccessible(true);

        @SuppressWarnings("unchecked")
        var result = (Consumer<String>) detectMethod.invoke(null, statusCode, isSlow);
        return result;
    }

    @Value
    @Builder
    public static class StatusSlownessData {

        int statusCode;
        boolean isSlow;

    }

}
