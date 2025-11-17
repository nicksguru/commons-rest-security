package guru.nicks.commons.security;

import guru.nicks.commons.utils.TextUtils;

import am.ik.yavi.meta.ConstraintArguments;
import com.google.common.collect.ImmutableSortedMap;
import jakarta.annotation.Nullable;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.ToIntFunction;

import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotBlank;
import static guru.nicks.commons.validation.dsl.ValiDsl.checkNotNull;

/**
 * Applies various settings to {@link HttpSecurity}. In each application, a {@link SecurityFilterChain} bean should be
 * created by calling {@link HttpSecurity#build()} of {@link #getHttpSecurity()}.
 */
@Slf4j
public class HttpSecurityConfigurer {

    public static final String EVERYTHING_MVC_PATTERN = "/**";

    @Getter
    private final HttpSecurity httpSecurity;

    private final boolean requireSsl;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    private final AtomicBoolean defaultAccessDenied = new AtomicBoolean(false);

    /**
     * Constructor.
     *
     * @param httpSecurity             {@link SecurityFilterChain} configurer
     * @param requireSsl               if {@code true}, all requests must come through HTTPS
     * @param authenticationEntryPoint authentication error handler (e.g. renders JSON to caller)
     *
     */
    @ConstraintArguments
    public HttpSecurityConfigurer(HttpSecurity httpSecurity, boolean requireSsl,
            AuthenticationEntryPoint authenticationEntryPoint) {
        this.httpSecurity = checkNotNull(httpSecurity, _HttpSecurityConfigurerArgumentsMeta.HTTPSECURITY.name());
        this.requireSsl = requireSsl;
        this.authenticationEntryPoint = checkNotNull(authenticationEntryPoint,
                _HttpSecurityConfigurerArgumentsMeta.AUTHENTICATIONENTRYPOINT.name());

        applyDefaults();
    }

    /**
     * Applies 'deny all' strategy to {code /**}. Should be called after all other rules because any rules put after
     * this one won't have any effect.
     *
     * @return {@code this}
     * @throws IllegalStateException {@code defaultAccessDenied} is {@code false}, but default access was already denied
     *                               earlier
     */
    public HttpSecurityConfigurer defaultAccessDenied(boolean defaultAccessDenied) {
        if (!defaultAccessDenied && this.defaultAccessDenied.get()) {
            throw new IllegalStateException("Default access was denied earlier, so it cannot be allowed");
        }

        if (defaultAccessDenied && this.defaultAccessDenied.compareAndSet(false, true)) {
            log.info("Protecting [{}]: denying everything not allowed above explicitly", EVERYTHING_MVC_PATTERN);

            try {
                httpSecurity.authorizeHttpRequests(registry ->
                        registry.anyRequest().denyAll());
            } catch (Exception e) {
                throw new SecurityException("Error applying 'default access denied': " + e.getMessage(), e);
            }
        }

        return this;
    }

    /**
     * Makes Spring Security aware of Basic authentication.
     *
     * @param realmName realm name
     * @return {@code this}
     */
    public HttpSecurityConfigurer withBasicAuthentication(String realmName) {
        try {
            httpSecurity.httpBasic(httpBasic ->
                    httpBasic.realmName(realmName)
                            .authenticationEntryPoint(authenticationEntryPoint));
        } catch (Exception e) {
            throw new SecurityException("Error configuring Basic authentication: " + e.getMessage(), e);
        }

        return this;
    }

    /**
     * Makes Spring Security aware of JWT authentication.
     *
     * @param jwtConverter converts JWT token to authentication
     * @return {@code this}
     */
    public HttpSecurityConfigurer withJwtAuthentication(Converter<Jwt, AbstractAuthenticationToken> jwtConverter) {
        try {
            httpSecurity.oauth2ResourceServer(server ->
                    server.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtConverter))
                            .authenticationEntryPoint(authenticationEntryPoint));
        } catch (Exception e) {
            throw new SecurityException(e.getMessage(), e);
        }

        return this;
    }

    /**
     * Applies the given array of Lambdas to this object.
     *
     * @param customizers Lambdas
     * @return {@code this}
     */
    @SafeVarargs
    public final HttpSecurityConfigurer withCustomizers(Consumer<? super HttpSecurityConfigurer>... customizers) {
        for (var customizer : customizers) {
            customizer.accept(this);
        }

        return this;
    }

    /**
     * Grants access to the given URLs to any authenticated (non-anonymous) user.
     *
     * @param mvcMatchers patterns, such as {@code /some/path/**} or {@code POST /some/path/**}
     * @return {@code this}
     */
    public HttpSecurityConfigurer protectWithAnyAuth(Collection<String> mvcMatchers) {
        return protectEndpoints(mvcMatchers);
    }

    /**
     * Shortcut to calling {@link #protectEndpoints(Collection, String...)} multiple times.
     *
     * @param authorityToMvcPatterns mapping of authorities (such as 'ROLE_xx') to URL patterns - will be sorted and
     *                               processed according to their priority, values are MVC patterns
     * @param authorityPriority      function to determine the priority of each authority
     * @return {@code this}
     * @throws IllegalArgumentException if two authorities have the same priority
     */
    public HttpSecurityConfigurer protectEndpoints(Map<String, List<String>> authorityToMvcPatterns,
            ToIntFunction<String> authorityPriority) {
        SortedMap<String, List<String>> sortedMap = ProtectionRuleSorter.sort(
                authorityToMvcPatterns, authorityPriority);

        sortedMap.forEach((authority, mvcPatterns) ->
                protectEndpoints(mvcPatterns, authority));

        return this;
    }

    /**
     * Allows access to the given URLs with ANY of the given user roles.
     *
     * @param mvcMatchers     patterns, such as {@code /some/path/**} or {@code POST /some/path} (the later will be
     *                        split into {@link HttpMethod} and URL pattern)
     * @param hasAnyAuthority user authorities - ANY of them grants access; empty array has a special meaning: it grants
     *                        access to all authenticated users
     * @return {@code this}
     * @throws IllegalStateException    'default access denied' is {@code true} (Allow rules are meaningless after
     *                                  Deny-all rule)
     * @throws IllegalArgumentException invalid definition (should be 'URL' or 'HttpMethod URL')
     */
    @ConstraintArguments
    public HttpSecurityConfigurer protectEndpoints(Collection<String> mvcMatchers, String... hasAnyAuthority) {
        checkNotNull(hasAnyAuthority, _HttpSecurityConfigurerProtectEndpointsArgumentsMeta.HASANYAUTHORITY.name());

        if (CollectionUtils.isEmpty(mvcMatchers)) {
            log.warn("No endpoints to protect with {}", ArrayUtils.isEmpty(hasAnyAuthority)
                    ? "'any auth'"
                    : hasAnyAuthority);
            return this;
        }

        if (defaultAccessDenied.get()) {
            throw new IllegalStateException("Deny-all rule already present. Put all Allow rules above it.");
        }

        try {
            httpSecurity.authorizeHttpRequests(registry ->
                    EndpointProtector.protect(registry, mvcMatchers, hasAnyAuthority));
        } catch (Exception e) {
            throw new SecurityException("Error protecting endpoints: " + e.getMessage(), e);
        }

        return this;
    }

    /**
     * Creates a request matcher for raw path patterns. Needed to protect paths belonging to 3rd party servlets.
     *
     * @param mvcPattern MVC pattern
     * @return request matcher
     */
    public RequestMatcher createRawPathMatcher(String mvcPattern) {
        MvcComponentsParser.validateMvcPattern(mvcPattern);

        return request -> {
            var matcher = new PathPatternParser().parse(mvcPattern);
            var path = ServletRequestPathUtils.parseAndCache(request);
            return matcher.matches(path);
        };
    }

    /**
     * Applies unified settings, such as turns off CSRF and session creation.
     */
    private void applyDefaults() {
        try {
            httpSecurity
                    // basic auth requires no CSRF protection
                    .csrf(AbstractHttpConfigurer::disable)
                    .formLogin(AbstractHttpConfigurer::disable)
                    // disable session creation - JWT tokens represent the state
                    .sessionManagement(sessionManagement ->
                            sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        } catch (Exception e) {
            throw new SecurityException("Error applying defaults: " + e.getMessage(), e);
        }

        // In older Spring Boot versions, 'security.requireSsl' property enforces HTTPS only if Basic Auth is
        // enabled. To stay on the safe side, HTTPS enforcement is carried out explicitly.
        if (requireSsl) {
            log.info("Enforcing HTTPS-only mode for all controllers");

            try {
                httpSecurity.redirectToHttps(Customizer.withDefaults());
            } catch (Exception e) {
                throw new SecurityException("Error enforcing HTTPS: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Represents a parsed MVC matcher with an optional HTTP method and a mandatory pattern.
     */
    @Value
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    private static class MvcComponents {

        /**
         * HTTP method for the matcher. Null if all HTTP methods match.
         */
        @Nullable
        HttpMethod httpMethod;

        /**
         * In the form of {@code /some/path/**} (no Ant regexps, only asterisks).
         */
        String mvcPattern;

        /**
         * Creates a matcher for URL pattern only (all HTTP methods).
         */
        static MvcComponents forMvcPattern(String pattern) {
            return new MvcComponents(null, pattern);
        }

        /**
         * Creates a matcher for specific HTTP method and URL pattern.
         */
        static MvcComponents forHttpMethodAndMvcPattern(HttpMethod httpMethod, String mvcPattern) {
            return new MvcComponents(httpMethod, mvcPattern);
        }

        /**
         * @return HTTP method for logging purposes (with ' ' appended, or empty string if it's {@code null})
         */
        @Override
        public String toString() {
            String prefix = (httpMethod == null)
                    ? ""
                    : (httpMethod + " ");
            return prefix + mvcPattern;
        }

    }

    /**
     * Handles parsing and validation of MVC matcher strings.
     */
    @UtilityClass
    private static class MvcComponentsParser {

        private static final Set<HttpMethod> KNOWN_HTTP_METHODS = Set.of(HttpMethod.values());
        private static final Set<Character> MVC_PATTERN_FORBIDDEN_CHARACTERS = Set.of('[', ']', '{', '}', '+', '?');

        /**
         * Parses MVC matcher string into components.
         *
         * @param mvcMatcher matcher string in format "URL" or "HttpMethod URL"
         * @return parsed matcher
         * @throws IllegalArgumentException if format is invalid
         */
        static MvcComponents parse(String mvcMatcher) {
            List<String> parts = TextUtils.splitByWhitespaces(mvcMatcher);

            return switch (parts.size()) {
                case 1 -> {
                    String pattern = validateMvcPattern(parts.get(0));
                    yield MvcComponents.forMvcPattern(pattern);
                }

                case 2 -> {
                    HttpMethod httpMethod = validateHttpMethod(parts.get(0));
                    String pattern = validateMvcPattern(parts.get(1));
                    yield MvcComponents.forHttpMethodAndMvcPattern(httpMethod, pattern);
                }

                default -> throw new IllegalArgumentException("Expecting 'URL' or 'HttpMethod URL' in: " + mvcMatcher);
            };
        }

        /**
         * Validates and converts HTTP method string.
         *
         * @param method HTTP method as string
         * @return validated HttpMethod
         * @throws IllegalArgumentException if method is unknown
         */
        private static HttpMethod validateHttpMethod(String method) {
            // accepts ARBITRARY string and creates HttpMethod on the fly
            HttpMethod httpMethod = HttpMethod.valueOf(method);

            if (!KNOWN_HTTP_METHODS.contains(httpMethod)) {
                throw new IllegalArgumentException("Unknown HTTP method: " + method);
            }

            return httpMethod;
        }

        /**
         * Validates MVC pattern to ensure it's not confused with Ant patterns.
         *
         * @param mvcPattern URL pattern
         * @return validated pattern
         * @throws IllegalArgumentException if pattern contains forbidden characters
         */
        private static String validateMvcPattern(String mvcPattern) {
            checkNotBlank(mvcPattern, "mvcPattern");

            if (mvcPattern.contains("..") || mvcPattern.contains("//") || mvcPattern.contains("\\")) {
                throw new IllegalArgumentException(
                        "MVC pattern contains suspicious characters that could lead to path traversal");
            }

            if (mvcPattern.chars().anyMatch(chr ->
                    MVC_PATTERN_FORBIDDEN_CHARACTERS.contains((char) chr))) {
                throw new IllegalArgumentException("MVC patterns are not Ant patterns - "
                        + "they cannot contain regexps, only '/**'");
            }

            return mvcPattern;
        }

    }

    /**
     * Handles role-based endpoint protection ordering according to their priority.
     */
    @UtilityClass
    private static class ProtectionRuleSorter {

        /**
         * Validates and sorts role-to-URL mappings by protection order.
         *
         * @param authorityToMvcPatterns mapping of authorities (such as 'ROLE_xx') to URL patterns
         * @param authorityPriority      function to determine the priority of each authority
         * @return sorted mapping (immutable)
         * @throws IllegalArgumentException if two authorities have the same priority
         */
        static SortedMap<String, List<String>> sort(Map<String, List<String>> authorityToMvcPatterns,
                ToIntFunction<String> authorityPriority) {
            if (MapUtils.isEmpty(authorityToMvcPatterns)) {
                return Collections.emptySortedMap();
            }

            var sortedMap = new ImmutableSortedMap.Builder<String, List<String>>(
                    Comparator.comparingInt(authorityPriority))
                    .putAll(authorityToMvcPatterns)
                    .buildOrThrow();

            log.info("Protecting endpoints in the following order (note overlapping URLs - order matters): {}",
                    sortedMap);
            return sortedMap;
        }

    }

    /**
     * Handles endpoint protection logic.
     */
    @UtilityClass
    private static class EndpointProtector {

        /**
         * Processes a single endpoint matcher and applies authorization rules.
         *
         * @param registry        authorization manager request matcher registry
         * @param mvcMatchers     URL patterns to protect
         * @param hasAnyAuthority user authorities ('any of') for this endpoint
         */
        static void protect(
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry,
                Collection<String> mvcMatchers, String[] hasAnyAuthority) {
            for (String mvcMatcher : mvcMatchers) {
                MvcComponents mvcComponents = MvcComponentsParser.parse(mvcMatcher);
                var authorizedUrl = createAuthorizedUrl(registry, mvcComponents);
                applyAuthorization(authorizedUrl, mvcComponents, hasAnyAuthority);
            }
        }

        /**
         * Creates authorized URL based on parsed matcher.
         *
         * @param registry      authorization manager request matcher registry
         * @param mvcComponents parsed MVC components (URL pattern and optional HTTP method)
         * @return authorized URL having methods to apply restrictions
         */
        private static AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl createAuthorizedUrl(
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry,
                MvcComponents mvcComponents) {
            PathPatternRequestMatcher requestMatcher = (mvcComponents.getHttpMethod() == null)
                    // any method + URL
                    ? PathPatternRequestMatcher
                    .withDefaults()
                    .matcher(mvcComponents.getMvcPattern())
                    // specific method + URL
                    : PathPatternRequestMatcher
                            .withDefaults()
                            .matcher(mvcComponents.getHttpMethod(), mvcComponents.getMvcPattern());
            return registry.requestMatchers(requestMatcher);
        }

        /**
         * Applies authorization rules to the authorized URL.
         *
         * @param authorizedUrl   authorized URL
         * @param hasAnyAuthority user authorities ('any of') for this endpoint
         */
        private static void applyAuthorization(
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl authorizedUrl,
                MvcComponents mvcComponents, String[] hasAnyAuthority) {
            if (hasAnyAuthority.length == 0) {
                log.info("Protecting [{}]: user must be authenticated", mvcComponents);
                authorizedUrl.authenticated();
            } else {
                log.info("Protecting [{}]: user must have any of authorities {}", mvcComponents, hasAnyAuthority);
                authorizedUrl.hasAnyAuthority(hasAnyAuthority);
            }
        }

    }

}
