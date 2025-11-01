package guru.nicks.security;

import guru.nicks.exception.BusinessException;
import guru.nicks.exception.http.UnauthorizedException;
import guru.nicks.rest.v1.dto.BusinessExceptionDto;

import am.ik.yavi.meta.ConstraintArguments;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nullable;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import java.io.IOException;
import java.util.function.BiFunction;
import java.util.function.Function;

import static guru.nicks.validation.dsl.ValiDsl.checkNotBlank;
import static guru.nicks.validation.dsl.ValiDsl.checkNotNull;

/**
 * Handles authentication errors by sending the exception DTO as JSON in {@link HttpServletResponse}. Also, if
 * application has 'global Basic Auth' enabled or the request URI belongs to Spring Boot Actuator, sends
 * {@code WWW-Authenticate: Basic} header, otherwise sends {@code WWW-Authenticate: Bearer}.
 */
public class BusinessExceptionAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String ACTUATOR_BASE_PATH = "/actuator";
    private static final String ACTUATOR_PATH_PREFIX = ACTUATOR_BASE_PATH + "/";

    private final BiFunction<? super Throwable, String, ? extends BusinessExceptionDto> exceptionDtoCreator;
    private final Function<BusinessException, HttpStatus> httpStatusCreator;

    private final AuthenticationEntryPoint bearerTokenDelegate = new BearerTokenAuthenticationEntryPoint();
    private final AuthenticationEntryPoint basicAuthDelegate;

    private final boolean hasGlobalBasicAuth;
    private final ObjectMapper objectMapper;

    /**
     * Constructor.
     *
     * @param exceptionDtoCreator given exception and request URI, creates a DTO to render in the JSON response
     * @param httpStatusCreator   given exception, creates ain HTTP status to return in the response
     * @param objectMapper        JSON generator
     * @param basicAuthRealm      realm for Basic Auth
     */
    @ConstraintArguments
    public BusinessExceptionAuthenticationEntryPoint(
            BiFunction<? super Throwable, String, ? extends BusinessExceptionDto> exceptionDtoCreator,
            Function<BusinessException, HttpStatus> httpStatusCreator,
            ObjectMapper objectMapper,
            String basicAuthRealm, boolean hasGlobalBasicAuth) {
        this.exceptionDtoCreator = checkNotNull(exceptionDtoCreator,
                _BusinessExceptionAuthenticationEntryPointArgumentsMeta.EXCEPTIONDTOCREATOR.name());
        this.httpStatusCreator = checkNotNull(httpStatusCreator,
                _BusinessExceptionAuthenticationEntryPointArgumentsMeta.HTTPSTATUSCREATOR.name());
        this.objectMapper = checkNotNull(objectMapper,
                _BusinessExceptionAuthenticationEntryPointArgumentsMeta.OBJECTMAPPER.name());

        checkNotBlank(basicAuthRealm, _BusinessExceptionAuthenticationEntryPointArgumentsMeta.BASICAUTHREALM.name());
        basicAuthDelegate = new CustomBasicAuthenticationEntryPoint(basicAuthRealm);
        this.hasGlobalBasicAuth = hasGlobalBasicAuth;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        AuthenticationEntryPoint delegate = (hasGlobalBasicAuth || isActuatorEndpoint(request.getRequestURI()))
                ? basicAuthDelegate
                : bearerTokenDelegate;

        try {
            delegate.commence(request, response, authException);
        } catch (IOException | ServletException e) {
            throw new SecurityException(e.getMessage(), e);
        }

        // find first businessException in chain
        BusinessException e = ExceptionUtils.getThrowableList(authException)
                .stream()
                .filter(BusinessException.class::isInstance)
                .map(BusinessException.class::cast)
                .findFirst()
                // exception has a cause whose message MAY be meaningful to user: 'Token expired', 'Malformed token',
                // but it's safer to hide it to avoid revealing something sensitive
                .orElseGet(() -> new UnauthorizedException(authException));

        response.setStatus(httpStatusCreator.apply(e).value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Object exceptionDto = exceptionDtoCreator.apply(e, request.getRequestURI());
        objectMapper.writeValue(response.getOutputStream(), exceptionDto);
    }

    /**
     * Determines whether the given request URI corresponds to a Spring Boot Actuator endpoint.
     * <p>
     * This method checks if the URI matches either the base actuator path ({@value ACTUATOR_BASE_PATH}) or any sub-path
     * under the actuator endpoint (starts with {@value ACTUATOR_PATH_PREFIX}).
     *
     * @param requestUri the request URI to check; may be {@code null}
     * @return {@code true} if the request URI is an actuator endpoint
     */
    private boolean isActuatorEndpoint(@Nullable String requestUri) {
        return (requestUri != null)
                &&
                (requestUri.equals(ACTUATOR_BASE_PATH) || requestUri.startsWith(ACTUATOR_PATH_PREFIX));
    }

    /**
     * As compared to parent class, does not print any HTML - the same JSON is printed for both Basic and Bearer auth.
     */
    private static class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

        private final String realmName;

        public CustomBasicAuthenticationEntryPoint(String realmName) {
            this.realmName = checkNotBlank(realmName, "realmName");
        }

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                AuthenticationException authException) {
            response.addHeader("WWW-Authenticate", "Basic realm=\"" + realmName + "\"");
        }

    }

}
