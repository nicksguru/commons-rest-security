package guru.nicks.security.filter;

import guru.nicks.ApplicationContextHolder;
import guru.nicks.log.domain.LogContext;
import guru.nicks.utils.HttpRequestUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.env.Environment;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;
import java.util.Optional;

/**
 * This filter does not auto-instantiate itself.
 * <p>
 * It's up to the custom security filter chain to insert this filter in the right position. The best fit is right before
 * {@link AuthorizationFilter} which actually grants/denies access (filters after that one aren't invoked if access is
 * denied)
 * <p>
 * What this class does is described in {@link #storeRequestParametersInMdc(HttpServletRequest)}.
 */
@Slf4j
public class LogContextFilter extends OncePerRequestFilter {

    /**
     * Stores the following optional attributes in {@link MDC}:
     * <ul>
     *  <li>{@link LogContext#APP_NAME} (as per {@code spring.application.name} in {@link Environment})</li>
     *  <li>{@link LogContext#REQUEST_PATH} ({@link HttpServletRequest#getRequestURI()})</li>
     *  <li>{@link LogContext#REQUEST_METHOD} ({@link HttpServletRequest#getMethod()})</li>
     *  <li>{@link LogContext#REMOTE_IP} (as per
     *      {@link HttpRequestUtils#getRemoteIpBehindProxy(HttpServletRequest)})</li>
     *  <li>{@link LogContext#USERNAME} (as per {@link HttpServletRequest#getUserPrincipal()})</li>
     * </ul>
     * Missing data (no app name / no username / no user ID / no user IP) cause the corresponding values to be wiped off
     * {@link LogContext} - it's crucial to delete the data pertinent to the previous request processed by the same
     * thread ({@link MDC} is thread-local).
     *
     * @param request HTTP request
     */
    public static void storeRequestParametersInMdc(HttpServletRequest request) {
        ApplicationContextHolder
                .findApplicationName()
                .ifPresent(LogContext.APP_NAME::put);

        LogContext.REQUEST_PATH.put(request.getRequestURI());
        LogContext.REQUEST_METHOD.put(request.getMethod());
        LogContext.REMOTE_IP.put(HttpRequestUtils.getRemoteIpBehindProxy(request));

        // by default, there's no user logged in
        LogContext.USERNAME.clear();

        Optional.ofNullable(request.getUserPrincipal())
                .map(Principal::getName)
                .ifPresent(LogContext.USERNAME::put);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        storeRequestParametersInMdc(request);
        filterChain.doFilter(request, response);
    }

}
