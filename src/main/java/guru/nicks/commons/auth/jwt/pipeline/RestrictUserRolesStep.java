package guru.nicks.commons.auth.jwt.pipeline;

import guru.nicks.commons.exception.user.UserAccountDisabledException;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.SetUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Checks {@link #getUserRoles(Object)} against a deny-list. Throws {@link UserAccountDisabledException}.
 */
@RequiredArgsConstructor
@Slf4j
public abstract class RestrictUserRolesStep<T, R> extends JwtAuthPipeline.Step<T> {

    private final Set<R> forbiddenRoles;

    protected RestrictUserRolesStep(@Nullable Collection<R> forbiddenRoles) {
        // normalize argument for logging purposes
        this.forbiddenRoles = new LinkedHashSet<>(
                Optional.ofNullable(forbiddenRoles)
                        .orElseGet(Collections::emptySet));
    }

    @Override
    public T apply(Jwt jwt, T userPrincipal) {
        checkUserRole(userPrincipal);
        return userPrincipal;
    }

    private void checkUserRole(T userPrincipal) {
        // empty list means all roles are allowed
        if (CollectionUtils.isEmpty(forbiddenRoles)) {
            return;
        }

        Set<R> roles = getUserRoles(userPrincipal);
        if (CollectionUtils.isEmpty(roles)) {
            return;
        }

        if (!SetUtils.intersection(forbiddenRoles, roles).isEmpty()) {
            log.debug("Role matches at least one of {}, rejecting role", forbiddenRoles);
            throw new UserAccountDisabledException();
        }
    }

    @Nullable
    protected abstract Set<R> getUserRoles(T userPrincipal);

}
