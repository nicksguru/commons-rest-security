package guru.nicks.commons.rest;

import guru.nicks.commons.exception.BusinessException;
import guru.nicks.commons.log.domain.LogContext;
import guru.nicks.commons.rest.dto.BusinessExceptionDto;
import guru.nicks.commons.security.filter.LogContextFilter;
import guru.nicks.commons.utils.ExceptionUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * @see #createExceptionDtoAndSetHttpStatus(Throwable, Class, Function, Consumer, Supplier, HttpServletRequest,
 *         HttpServletResponse)
 */
@UtilityClass
@Slf4j
public class ExceptionDtoCreator {

    /**
     * Pre-compiled pattern for sanitizing HTTP header names and values. Matches carriage return (CR), line feed (LF),
     * and null characters to prevent HTTP response splitting attacks.
     * <p>
     * This pattern is compiled once and reused for all sanitization operations, improving performance compared to
     * {@link String#replaceAll(String, String)} which recompiles the pattern on each invocation.
     */
    private static final Pattern HEADER_SANITIZATION_PATTERN = Pattern.compile("[\r\n\0]");

    /**
     * Creates exception DTO and sets both HTTP status response header (using {@link BusinessExceptionDto#errorCode()})
     * and additional headers (if {@code cause} is a {@link BusinessException} and has valid
     * {@link BusinessException#getAdditionalResponseHeaders()}).
     * <p>
     * Additionally, calls {@link LogContextFilter#storeRequestParametersInMdc(HttpServletRequest)} to ensure that auth
     * errors have things like request IP logged (Spring Security may step in too early and ignore this filter).
     *
     * @param cause                error cause
     * @param errorCodeClass       enum class {@link BusinessExceptionDto#errorCode()} should be parsed into
     * @param httpStatusMapper     maps {@code E} to {@link HttpStatus}
     * @param errorMessageConsumer receives error message if the log level is 'error' (messages with other log levels
     *                             are logged, but error messages are not, they're only passed to this consumer)
     * @param dtoSupplier          exception DTO creator
     * @param request              HTTP request
     * @param response             HTTP response
     * @param <E>                  error code type
     * @return exception DTO
     */
    public static <E extends Enum<E>> BusinessExceptionDto createExceptionDtoAndSetHttpStatus(Throwable cause,
            Class<E> errorCodeClass, Function<E, HttpStatus> httpStatusMapper,
            Consumer<String> errorMessageConsumer, Supplier<BusinessExceptionDto> dtoSupplier,
            HttpServletRequest request, HttpServletResponse response) {
        // see method comment
        LogContextFilter.storeRequestParametersInMdc(request);

        cause = ExceptionUtils.unwrapInvocationTargetException(cause);
        // set response headers if their names and values are not blank
        if (cause instanceof BusinessException businessException) {
            setAdditionalResponseHeaders(businessException, response);
        }

        BusinessExceptionDto errorDto = dtoSupplier.get();
        E errorCode = tryParseErrorCode(errorDto, errorCodeClass);

        response.setStatus(httpStatusMapper.apply(errorCode).value());
        LogContext.RESPONSE_HTTP_STATUS.put(response.getStatus());

        var message = String.format(Locale.US, "Rendering %s because of %s", errorDto,
                ExceptionUtils.formatWithCompactStackTrace(cause));

        // null if there's no such status in enum
        var httpStatus = HttpStatus.resolve(response.getStatus());

        // The message must ALWAYS be logged, otherwise the stack trace will be hidden. Also, set level=error on 5xx
        // status only, otherwise all '400 Bad Request' responses will be treated as app errors by log monitors.
        if ((httpStatus != null) && httpStatus.is5xxServerError()) {
            errorMessageConsumer.accept(message);
        } else if ((httpStatus != null) && httpStatus.is4xxClientError()) {
            log.warn(message);
        } else {
            log.info(message);
        }

        return errorDto;
    }

    /**
     * Safely sets response headers from business exception, with validation and sanitization. Any errors raised in
     * {@link HttpServletResponse#setHeader(String, String)} are ignored, so the response is sent in any case, even
     * without the additional headers.
     *
     * @param businessException the exception containing headers
     * @param response          the HTTP response
     */
    private static void setAdditionalResponseHeaders(BusinessException businessException,
            HttpServletResponse response) {
        Map<String, Object> headers = businessException.getAdditionalResponseHeaders();

        if (headers == null) {
            return;
        }

        headers.forEach((name, value) -> {
            String sanitizedName = sanitizeHeaderNameOrValue(name);

            if (sanitizedName != null) {
                String sanitizedValue = sanitizeHeaderNameOrValue(value);

                if (sanitizedValue != null) {
                    response.setHeader(sanitizedName, sanitizedValue);
                }
            }
        });
    }

    /**
     * Sanitizes header name or value to prevent HTTP response splitting attacks according to
     * {@link #HEADER_SANITIZATION_PATTERN}.
     *
     * @param input header name or value
     * @return sanitized input, or {@code null} if input is blank
     */
    private static String sanitizeHeaderNameOrValue(Object input) {
        String str = Objects.toString(input, "");
        str = HEADER_SANITIZATION_PATTERN.matcher(str).replaceAll("");

        if (StringUtils.isBlank(str)) {
            str = null;
        }

        return str;
    }

    /**
     * Attempts to parse {@link BusinessExceptionDto#errorCode()} into a constant of the given enum type.
     *
     * @param errorDto       exception DTO to parse error code from, may be {@code null}
     * @param errorCodeClass enum class the error code should be parsed into
     * @param <E>            error code type
     * @return parsed error code, or {@code null} if the DTO or its error code is missing, or parsing fails
     */
    private static <E extends Enum<E>> E tryParseErrorCode(BusinessExceptionDto errorDto, Class<E> errorCodeClass) {
        if ((errorDto == null) || (errorDto.errorCode() == null)) {
            return null;
        }

        try {
            // throws IllegalArgumentException for unknown constant names
            return Enum.valueOf(errorCodeClass, errorDto.errorCode());
        } catch (IllegalArgumentException e) {
            log.error("Failed to restore exception from error code '{}' (ignoring this error): {}",
                    errorDto.errorCode(), e.getMessage(), e);

            return null;
        }
    }

}
