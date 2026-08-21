package guru.nicks.commons.cucumber;

import guru.nicks.commons.cucumber.world.TextWorld;
import guru.nicks.commons.exception.BusinessException;
import guru.nicks.commons.log.domain.LogContext;
import guru.nicks.commons.rest.ExceptionDtoCreator;
import guru.nicks.commons.rest.dto.BusinessExceptionDto;

import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Step definitions for testing {@link ExceptionDtoCreator}.
 */
@RequiredArgsConstructor
public class ExceptionDtoCreatorSteps {

    private static final String REQUEST_URI = "/api/test";

    // DI
    private final TextWorld textWorld;
    private final List<String> errorMessages = new ArrayList<>();
    private final List<TestErrorCode> mapperArguments = new ArrayList<>();
    /**
     * Maps error codes to HTTP statuses, recording its arguments; a missing (null) error code is rendered as a 5xx
     * error.
     */
    private final Function<TestErrorCode, HttpStatus> httpStatusMapper = errorCode -> {
        mapperArguments.add(errorCode);

        // null means the DTO error code is missing or unknown - such errors are rendered as 5xx
        return (errorCode == null)
                ? HttpStatus.INTERNAL_SERVER_ERROR
                : errorCode.getHttpStatus();
    };
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private Throwable cause;
    private Throwable originalCause;
    private BusinessExceptionDto errorDto;
    private BusinessExceptionDto returnedDto;

    /**
     * Resets the scenario state, including {@link MDC} which is thread-local and may leak between scenarios.
     */
    @Before
    public void beforeEachScenario() {
        MDC.clear();

        request = new MockHttpServletRequest("GET", REQUEST_URI);
        response = new MockHttpServletResponse();

        errorMessages.clear();
        mapperArguments.clear();

        cause = null;
        originalCause = null;
        errorDto = null;
        returnedDto = null;
    }

    /**
     * Clears {@link MDC} to prevent leakage into other scenarios.
     */
    @After
    public void afterEachScenario() {
        MDC.clear();
    }

    /**
     * Creates a plain (non-business) exception to be used as the error cause.
     *
     * @param exceptionType exception simple name
     * @param message       exception message
     */
    @Given("a cause exception of type {word} with message {string}")
    public void aCauseExceptionOfTypeWithMessage(String exceptionType, String message) {
        cause = switch (exceptionType) {
            case "RuntimeException" -> new RuntimeException(message);
            case "IllegalStateException" -> new IllegalStateException(message);
            default -> throw new IllegalArgumentException("Unknown exception type: " + exceptionType);
        };
    }

    /**
     * Creates a business exception bearing a single additional response header. Numeric values are converted to
     * integers on purpose to exercise non-string header values.
     *
     * @param name  header name (may contain escape sequences: {@code \r}, {@code \n}, {@code \0})
     * @param value header value (may contain the same escape sequences)
     */
    @Given("a business exception with an additional response header {string} and value {string}")
    public void aBusinessExceptionWithAnAdditionalResponseHeaderAndValue(String name, String value) {
        cause = new TestBusinessException(Map.of(unescape(name), toHeaderValue(value)));
    }

    /**
     * Creates a business exception whose additional response headers map is null.
     */
    @Given("a business exception without additional response headers")
    public void aBusinessExceptionWithoutAdditionalResponseHeaders() {
        cause = new TestBusinessException();
    }

    /**
     * Remembers the current cause and wraps it into an {@link InvocationTargetException}, like reflection does.
     */
    @Given("the cause is wrapped in an InvocationTargetException")
    public void theCauseIsWrappedInAnInvocationTargetException() {
        originalCause = cause;
        cause = new InvocationTargetException(cause);
    }

    /**
     * Creates the exception DTO supplied to the method under test; a blank error code means no error code at all.
     *
     * @param errorCode error code to put into the DTO
     */
    @Given("an error DTO with error code {string}")
    public void anErrorDtoWithErrorCode(String errorCode) {
        errorDto = BusinessExceptionDto.builder()
                .errorCode(StringUtils.isNotBlank(errorCode) ? errorCode : null)
                .message("test message")
                .build();
    }

    /**
     * Creates the exception DTO supplied to the method under test, without an error code.
     */
    @Given("an error DTO without an error code")
    public void anErrorDtoWithoutAnErrorCode() {
        errorDto = BusinessExceptionDto.builder()
                .message("test message")
                .build();
    }

    /**
     * Invokes the method under test, capturing messages passed to the error message consumer.
     */
    @When("the exception DTO is created and HTTP status is set")
    public void theExceptionDtoIsCreatedAndHttpStatusIsSet() {
        textWorld.setLastException(catchThrowable(() ->
                returnedDto = ExceptionDtoCreator.createExceptionDtoAndSetHttpStatus(
                        cause, TestErrorCode.class, httpStatusMapper, errorMessages::add, () -> errorDto, request,
                        response)));
    }

    /**
     * Checks the HTTP status set on the response.
     *
     * @param expectedStatus expected HTTP status
     */
    @Then("the response HTTP status should be {int}")
    public void theResponseStatusShouldBe(int expectedStatus) {
        assertThat(response.getStatus())
                .as("response status")
                .isEqualTo(expectedStatus);
    }

    /**
     * Checks that the method under test returns the DTO created by the supplier as-is.
     */
    @Then("the returned DTO should be the same object as the supplier's DTO")
    public void theReturnedDtoShouldBeTheSameObjectAsTheSuppliersDto() {
        assertThat(returnedDto)
                .as("returned DTO")
                .isSameAs(errorDto);
    }

    /**
     * Checks the HTTP status stored in the log context.
     *
     * @param expectedStatus expected HTTP status
     */
    @Then("the log context should contain response status {int}")
    public void theLogContextShouldContainResponseStatus(int expectedStatus) {
        assertThat(LogContext.RESPONSE_HTTP_STATUS.find())
                .as("response status in log context")
                .hasValue(String.valueOf(expectedStatus));
    }

    /**
     * Checks whether the error message consumer was invoked (5xx errors only).
     *
     * @param invoked expected consumer invocation flag
     */
    @Then("the error message consumer should be invoked: {booleanValue}")
    public void theErrorMessageConsumerShouldBeInvoked(boolean invoked) {
        assertThat(errorMessages)
                .as("messages passed to the error message consumer")
                .hasSize(invoked ? 1 : 0);
    }

    /**
     * Checks that the error message consumer received a single message naming both the DTO and the cause.
     */
    @Then("the error message consumer should be invoked once with a message containing the DTO and the cause")
    public void theErrorMessageConsumerShouldBeInvokedOnceWithAMessageContainingTheDtoAndTheCause() {
        var expectedCause = (originalCause != null) ? originalCause : cause;

        assertThat(errorMessages)
                .as("messages passed to the error message consumer")
                .hasSize(1);

        assertThat(errorMessages.getFirst())
                .as("error message")
                .contains(errorDto.toString())
                .contains(expectedCause.getClass().getName());
    }

    /**
     * Checks that the error message consumer received a message containing the given fragment.
     *
     * @param fragment expected message fragment
     */
    @Then("the error message consumer should be invoked with a message containing {string}")
    public void theErrorMessageConsumerShouldBeInvokedWithAMessageContaining(String fragment) {
        assertThat(errorMessages)
                .as("messages passed to the error message consumer")
                .isNotEmpty();

        assertThat(errorMessages.getFirst())
                .as("error message")
                .contains(fragment);
    }

    /**
     * Checks that the error message consumer was not invoked (non-5xx errors are only logged).
     */
    @Then("the error message consumer should not be invoked")
    public void theErrorMessageConsumerShouldNotBeInvoked() {
        assertThat(errorMessages)
                .as("messages passed to the error message consumer")
                .isEmpty();
    }

    /**
     * Checks that the HTTP status mapper received a null error code (missing or unknown DTO error code).
     */
    @Then("the HTTP status mapper should be invoked with a null error code")
    public void theHttpStatusMapperShouldBeInvokedWithANullErrorCode() {
        assertThat(mapperArguments)
                .as("error codes passed to the HTTP status mapper")
                .containsExactly((TestErrorCode) null);
    }

    /**
     * Checks a header set on the response from the business exception's additional response headers.
     *
     * @param name          expected header name
     * @param expectedValue expected header value
     */
    @Then("the response should contain header {string} with value {string}")
    public void theResponseShouldContainHeaderWithValue(String name, String expectedValue) {
        assertThat(response.getHeader(name))
                .as("response header '" + name + "'")
                .isEqualTo(expectedValue);
    }

    /**
     * Checks that no additional response headers were set.
     */
    @Then("the response should contain no additional headers")
    public void theResponseShouldContainNoAdditionalHeaders() {
        assertThat(response.getHeaderNames())
                .as("response header names")
                .isEmpty();
    }

    /**
     * Converts escape sequences ({@code \r}, {@code \n}, {@code \0}) typed in feature files into control characters
     * which Gherkin cannot hold directly.
     *
     * @param raw string from a feature file
     * @return string with escape sequences replaced by control characters
     */
    private String unescape(String raw) {
        return raw
                .replace("\\r", "\r")
                .replace("\\n", "\n")
                .replace("\\0", "\0");
    }

    /**
     * Converts a feature file string into a header value, deliberately returning an integer for numeric strings to
     * exercise non-string header values.
     *
     * @param raw string from a feature file
     * @return header value (string or integer)
     */
    private Object toHeaderValue(String raw) {
        String value = unescape(raw);

        return value.matches("-?\\d+")
                ? Integer.valueOf(value)
                : value;
    }

    /**
     * Error codes the DTO error code is parsed into, each bound to the HTTP status the mapper returns.
     */
    @RequiredArgsConstructor
    private enum TestErrorCode {

        VALIDATION_FAILED(HttpStatus.BAD_REQUEST),
        ENTITY_NOT_FOUND(HttpStatus.NOT_FOUND),
        REDIRECT(HttpStatus.FOUND),
        SUCCESS(HttpStatus.OK),
        INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR),
        SERVICE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE);

        @Getter
        private final HttpStatus httpStatus;

    }

    /**
     * Business exception fixture exposing additional response headers constructors.
     */
    private static class TestBusinessException extends BusinessException {

        TestBusinessException() {
            super();
        }

        TestBusinessException(Map<String, Object> additionalResponseHeaders) {
            super(additionalResponseHeaders);
        }

    }

}
