package guru.nicks.auth.jwt.pipeline;

import guru.nicks.exception.user.UserAccountDisabledException;

import com.google.common.collect.ImmutableSortedSet;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Checks {@link #getUsername(Object)} against a deny-list. Throws {@link UserAccountDisabledException}.
 */
@RequiredArgsConstructor
@Slf4j
public abstract class RestrictUsernameStep<T> extends JwtAuthPipeline.Step<T> {

    /**
     * {@link #getUsername(Object)} (case-insensitive!) not allowed to authenticate; empty means no restriction.
     */
    private final Set<String> forbiddenUsernames;

    public RestrictUsernameStep(@Nullable Collection<String> forbiddenUsernames) {
        // normalize argument
        Set<String> tmpUsernames = Optional.ofNullable(forbiddenUsernames)
                .orElseGet(Collections::emptyList)
                .stream()
                // blank usernames are ignored
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toSet());
        this.forbiddenUsernames = ImmutableSortedSet.copyOf(tmpUsernames);
    }

    @Override
    public T apply(Jwt jwt, T userPrincipal) {
        checkUsername(userPrincipal);
        return userPrincipal;
    }

    private void checkUsername(T userPrincipal) {
        // empty list means all usernames are allowed
        if (CollectionUtils.isEmpty(forbiddenUsernames)) {
            return;
        }

        String username = getUsername(userPrincipal);

        if (StringUtils.isBlank(username)) {
            throw new UserAccountDisabledException("Missing username");
        }

        if (forbiddenUsernames
                .stream()
                .anyMatch(username::equalsIgnoreCase)) {
            log.debug("Username matches at least one of {}, rejecting username", forbiddenUsernames);
            throw new UserAccountDisabledException();
        }
    }

    @Nullable
    protected abstract String getUsername(T userPrincipal);

}
