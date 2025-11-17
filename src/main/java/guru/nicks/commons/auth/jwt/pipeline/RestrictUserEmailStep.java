package guru.nicks.commons.auth.jwt.pipeline;

import guru.nicks.commons.exception.auth.EmailNotAllowedException;

import jakarta.annotation.Nullable;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Checks {@link #getUserEmail(Object)} against allowed patterns (<b>empty/null list means no emails)</b>. Throws
 * {@link EmailNotAllowedException}.
 */
@RequiredArgsConstructor
@Slf4j
public abstract class RestrictUserEmailStep<T> extends JwtAuthPipeline.Step<T> {

    /**
     * Needed for debugging only. The check is performed by {@link #isEmailAllowed}.
     */
    @Getter(AccessLevel.PROTECTED)
    private final Set<String> allowedEmailPatterns;

    /**
     * Checks if user email is allowed. Inside is a composite predicate performing PARTIAL matching (as per
     * {@link Matcher#find()}): '^' and '$' are optional but desirable for better accuracy.
     */
    @Getter(AccessLevel.PROTECTED)
    private final Predicate<String> isEmailAllowed;

    protected RestrictUserEmailStep(@Nullable Collection<String> allowedEmailPatterns) {
        // normalize argument
        Set<String> tmpEmails = Optional.ofNullable(allowedEmailPatterns)
                .orElseGet(Collections::emptyList)
                .stream()
                // blank patterns are ignored
                .filter(StringUtils::isNotBlank)
                // retain element order (for debugging - comparison result MAY depend on the element order if a
                // broader-scoped regexp goes first)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        this.allowedEmailPatterns = Collections.unmodifiableSet(tmpEmails);

        isEmailAllowed = this.allowedEmailPatterns.stream()
                .map(Pattern::compile)
                .map(Pattern::asPredicate)
                .reduce(Predicate::or)
                .orElseGet(() -> anyEmailAddress -> true);
    }

    @Override
    public T apply(Jwt jwt, T userPrincipal) {
        checkUserEmail(userPrincipal);
        return userPrincipal;
    }

    protected void checkUserEmail(T userPrincipal) {
        String email = getUserEmail(userPrincipal);

        if (StringUtils.isBlank(email)) {
            throw new EmailNotAllowedException("Missing user email address");
        }

        // nothing is allowed
        if (CollectionUtils.isEmpty(allowedEmailPatterns)) {
            throw new EmailNotAllowedException();
        }

        // don't call error(), as log analyzers would treat it as app error
        if (!isEmailAllowed.test(email)) {
            log.debug("User email address matches none of {}", allowedEmailPatterns);
            throw new EmailNotAllowedException();
        }
    }

    @Nullable
    protected abstract String getUserEmail(T userPrincipal);

}
