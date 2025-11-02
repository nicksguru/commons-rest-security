package guru.nicks.security.filter;

import guru.nicks.auth.domain.CorsProperties;
import guru.nicks.utils.HttpRequestUtils;

import am.ik.yavi.meta.ConstraintArguments;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.IOException;
import java.util.Optional;

import static guru.nicks.validation.dsl.ValiDsl.checkNotNull;

/**
 * This filter does not auto-instantiate itself.
 * <p>
 * Sets {@code Access-Control-Allow-Origin} to the {@code Origin} request header, thus bypassing the '* or one domain'
 * restriction: if there's no {@code Origin} header in request, does nothing because this isn't a cross-domain request;
 * if {@link CorsProperties#getOriginAllowList()} is '*', sets the header to request's {@code Origin}.
 * <p>
 * It's better to offload {@code OPTIONS} method handling to a proxy (to respond to pre-flight requests sent by browsers
 * before they issue payload-carrying requests). However, this filter is still necessary for post-processing:
 * payload-carrying CORS responses must have {@code Access-Control-Allow-Origin} too - see
 * <a href="https://www.html5rocks.com/en/tutorials/cors">details</a>.
 * <p>
 * WARNING: filter order must be as low as possible - in order to step in before Spring Security. Otherwise 401 errors
 * won't have {@code Access-Control-Allow-Origin} header set, which will prevent web apps from parsing authentication
 * failures (browsers will reject such queries on CORS grounds, so the responses won't reach the web apps).
 */
@Slf4j
public class CustomCorsFilter extends CorsFilter {

    private final CorsConfigurationSource configSource;

    @ConstraintArguments
    public CustomCorsFilter(CorsConfigurationSource configSource) {
        super(configSource);
        this.configSource = checkNotNull(configSource, _CustomCorsFilterArgumentsMeta.CONFIGSOURCE.name());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CorsConfiguration corsConfig = configSource.getCorsConfiguration(request);

        // config may vary per request (null isn't supposed to appear, but just in case)
        if (corsConfig == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String origin = request.getHeader(HttpHeaders.ORIGIN);
        // don't set CORS headers if this isn't a cross-domain request
        if (StringUtils.isBlank(origin)) {
            filterChain.doFilter(request, response);
            return;
        }

        // mirror Origin for both preflight and payload-carrying methods if:
        // 1. either any origin is allowed (don't just set '*' - see
        //    https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSMissingAllowOrigin)
        // 2. or origin is in allow-list
        if (originAccepted(origin, corsConfig)) {
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            response.setHeader(HttpHeaders.VARY, "Origin");
        } else {
            log.warn("Origin '{}' rejected", origin);
        }

        // OPTIONS method is terminated right here
        if ("OPTIONS".equals(request.getMethod())) {
            renderOptionsResponse(response, corsConfig);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void renderOptionsResponse(HttpServletResponse response, CorsConfiguration corsConfig) {
        HttpRequestUtils.setNonBlankHeader(response, HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                corsConfig.getAllowedMethods());
        HttpRequestUtils.setNonBlankHeader(response, HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                corsConfig.getAllowedHeaders());

        response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                Boolean.TRUE.equals(corsConfig.getAllowCredentials()) ? "true" : "false");
        response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE,
                Optional.ofNullable(corsConfig.getMaxAge())
                        .map(Object::toString)
                        .orElse("0"));

        response.setHeader(HttpHeaders.CONTENT_LENGTH, "0");
        response.setHeader(HttpHeaders.CONTENT_TYPE, "text/plain; charset=UTF-8");
        // can be NO_CONTENT as well, but OK is safer for dealing with a wider set of clients
        response.setStatus(HttpStatus.OK.value());
    }

    private boolean originAccepted(String origin, CorsConfiguration corsConfig) {
        return corsConfig.checkOrigin(origin) != null;
    }

}
