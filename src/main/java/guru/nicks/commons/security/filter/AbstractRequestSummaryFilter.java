package guru.nicks.commons.security.filter;

import guru.nicks.commons.rest.RequestSummaryLogger;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriConsumer;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This filter does not auto-instantiate itself.
 * <p>
 * Logs request summary (e.g. method, status code, duration).
 *
 * @see RequestSummaryLogger
 */
@RequiredArgsConstructor
@Slf4j
public abstract class AbstractRequestSummaryFilter extends OncePerRequestFilter {

    @NonNull // Lombok creates runtime nullness check for this own annotation only
    private final RequestSummaryLogger requestSummaryLogger;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // at this moment, there's no user-related information available, but the request URL is known, including
        // static (e.g. Swagger) resources that don't require authentication and yield '304 Not Modified'
        LogContextFilter.storeRequestParametersInMdc(request);

        var responseWrapper = new LoggingResponseWrapper(request.getRequestURI(), Instant.now(),
                response, requestSummaryLogger);
        filterChain.doFilter(request, responseWrapper);
    }

    /**
     * Without this wrapper, it's impossible to set response headers (controllers have flushed their buffers already).
     */
    private static class LoggingResponseWrapper extends HttpServletResponseWrapper {

        private final AtomicBoolean alreadyLogged = new AtomicBoolean();

        private final String requestUri;
        private final Instant startInstant;
        private final TriConsumer<String, HttpServletResponse, Duration> requestDurationConsumer;

        public LoggingResponseWrapper(String requestUri, Instant startInstant, HttpServletResponse response,
                TriConsumer<String, HttpServletResponse, Duration> requestDurationConsumer) {
            super(response);

            // no validation for speed reasons
            this.requestUri = requestUri;
            this.startInstant = startInstant;
            this.requestDurationConsumer = requestDurationConsumer;
        }

        /**
         * Called for endpoints that render a body. Doesn't add response rendering time to the total time, as this hook
         * is called earlier.
         */
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            ServletOutputStream outputStream = super.getOutputStream();
            consumeMillisElapsedOnce();
            return outputStream;
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            consumeMillisElapsedOnce();
            super.sendError(sc, msg);
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            consumeMillisElapsedOnce();
            super.sendRedirect(location);
        }

        /**
         * Called for endpoints that don't render a body. For some reason, not called for those that do.
         */
        @Override
        public void setStatus(int sc) {
            // set new status, then log the new status
            super.setStatus(sc);
            consumeMillisElapsedOnce();
        }

        private void consumeMillisElapsedOnce() {
            try {
                if (alreadyLogged.compareAndSet(false, true)) {
                    requestDurationConsumer.accept(requestUri, this, Duration.between(startInstant, Instant.now()));
                }
            } catch (RuntimeException e) {
                log.error("Failed to log request summary: {}", e.getMessage(), e);
            }
        }

    }

}
