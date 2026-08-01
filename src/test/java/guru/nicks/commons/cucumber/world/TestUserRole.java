package guru.nicks.commons.cucumber.world;

import guru.nicks.commons.auth.domain.CommonsUserPrincipal;

/**
 * Test user role enum for testing {@link CommonsUserPrincipal}.
 */
public enum TestUserRole {

    ROLE_USER,
    ROLE_ADMIN,
    ROLE_MODERATOR,
    ROLE_SUPER_ADMIN,
    ROLE_GUEST

}
