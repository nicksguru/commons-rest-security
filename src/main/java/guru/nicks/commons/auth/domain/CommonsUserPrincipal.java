package guru.nicks.commons.auth.domain;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.SequencedSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Enhanced user principal that combines Spring Security's {@link UserDetails} and OAuth2's
 * {@link OAuth2AuthenticatedPrincipal} with OpenID Connect user profile information.
 * <p>
 * This class provides a comprehensive representation of an authenticated user, supporting both traditional
 * username/password authentication and OAuth2 / OpenID Connect flows. Objects of this class are immutable except for
 * the password - see {@link #eraseCredentials()}.
 * <p>
 * WARNING: {@link #equals(Object)} and {@link #hashCode()} methods are implemented the same way as in {@link User}:
 * they consider the {@link #getUsername() username} only!
 *
 * @see UserDetails
 * @see OAuth2AuthenticatedPrincipal
 * @see OpenIdUserProfile
 */
@SuperBuilder(toBuilder = true)
@FieldNameConstants
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class CommonsUserPrincipal<R extends Enum<R>>
        implements OpenIdUserProfile<R>, OAuth2AuthenticatedPrincipal, UserDetails, CredentialsContainer {

    /**
     * User ID. Under the hood, this can for example be a UUID, but in a string form anyway.
     */
    @Getter(onMethod_ = @Override)
    private final String id;

    /**
     * Username (must not be blank).
     */
    @EqualsAndHashCode.Include
    @Getter(onMethod_ = @Override)
    private final String username;

    /**
     * Email address.
     */
    @Getter(onMethod_ = @Override)
    private final String email;

    /**
     * {@code true} if email address has been verified by {@link #getJwtProvider()}
     */
    @Getter(onMethod_ = @Override)
    private final boolean emailVerified;

    /**
     * First name.
     */
    @Getter(onMethod_ = @Override)
    private final String firstName;

    /**
     * Last name.
     */
    @Getter(onMethod_ = @Override)
    private final String lastName;

    /**
     * Full name (not necessarily first + last).
     */
    @Getter(onMethod_ = @Override)
    private final String fullName;

    /**
     * 2-letter ISO code, such as 'en'.
     */
    @Getter(onMethod_ = @Override)
    private final String languageCode;

    /**
     * Link to profile picture.
     */
    @Getter(onMethod_ = @Override)
    private final String pictureLink;

    /**
     * Foreign JWT provider ({@code null} for local users).
     */
    @Getter
    private final JwtProvider jwtProvider;

    /**
     * Arbitrary attributes, such as JWT claims. Immutable or {@code null}.
     */
    @Getter(onMethod_ = @Override)
    private final Map<String, Object> attributes;

    /**
     * User roles (will be sorted, for predictable iteration order). Immutable or {@code null}.
     */
    @Getter(onMethod_ = @Override)
    private final SortedSet<R> roles;

    /**
     * Granted authorities derived from roles. Immutable or {@code null}.
     */
    @Getter(onMethod_ = @Override)
    private final Set<GrantedAuthority> authorities;

    /**
     * For {@link UserDetails#isAccountNonExpired()}. Default is {@code true}.
     */
    @Getter(onMethod_ = @Override)
    @Builder.Default
    private final boolean accountNonExpired = false;

    /**
     * For {@link UserDetails#isAccountNonLocked()}. Default is {@code true}.
     */
    @Getter(onMethod_ = @Override)
    @Builder.Default
    private final boolean accountNonLocked = false;

    /**
     * For {@link UserDetails#isCredentialsNonExpired()}. Default is {@code true}.
     */
    @Getter(onMethod_ = @Override)
    @Builder.Default
    private final boolean credentialsNonExpired = false;

    /**
     * For {@link UserDetails#isEnabled()}. Default is {@code true}.
     */
    @Getter(onMethod_ = @Override)
    @Builder.Default
    private final boolean enabled = false;

    /**
     * Password ({@code null} will be converted to an empty string to follow the behavior of {@link User} class).
     * <p>
     * This field is not final because of {@link #eraseCredentials()}.
     */
    @Getter(onMethod_ = @Override)
    @ToString.Exclude
    private String password;

    @Override
    public String getName() {
        return getUsername();
    }

    /**
     * Sets {@link #getPassword()} to {@code null}.
     */
    @Override
    public void eraseCredentials() {
        password = null;
    }

    /**
     * @return {@code true} if {@link #getJwtProvider()} is not {@code null}
     */
    public boolean isForeignJwt() {
        return getJwtProvider() != null;
    }

    /**
     * Custom builder methods to sort roles and authorities before storing them.
     */
    @SuppressWarnings("UnusedReturnValue") // OK for builders
    public abstract static class CommonsUserPrincipalBuilder<
            R extends Enum<R>,
            C extends CommonsUserPrincipal<R>,
            B extends CommonsUserPrincipalBuilder<R, C, B>> {

        /**
         * Replaces null password with empty string to follow the behavior of {@link User} class.
         *
         * @param password password
         * @return this builder instance
         */
        public B password(String password) {
            this.password = (password == null)
                    ? ""
                    : password;
            return self();
        }

        /**
         * Sets user roles after sorting them for predictable iteration order. Also, sets authorities based on
         * {@link R#name()}.
         *
         * @param roles user roles (will be sorted; {@code null} will be converted to an empty set)
         * @return this builder instance
         */
        public B roles(Collection<R> roles) {
            // must never be null
            this.roles = (roles == null)
                    ? null
                    : (roles instanceof SortedSet<R> s)
                            ? Collections.unmodifiableSortedSet(s)
                            : Collections.unmodifiableSortedSet(new TreeSet<>(roles));

            // derive authorities from roles (sort by name because SimpleGrantedAuthority is not Comparable)
            if (this.roles == null) {
                authorities(null);
            } else {
                authorities(AuthorityUtils.createAuthorityList(
                        this.roles.stream()
                                .map(R::name)
                                .sorted()
                                .toList()));
            }

            return self();
        }

        /**
         * Sets granted authorities after sorting them for predictable iteration order. Generally, this method should
         * not be called because roles define authorities, and should be kept in sync. However, {@link #toBuilder()}
         * needs this.
         *
         * @param authorities granted authorities (will be sorted; {@code null} will be converted to an empty set)
         * @return this builder instance
         */
        public B authorities(Collection<GrantedAuthority> authorities) {
            // must never be null
            this.authorities = (authorities == null)
                    ? null
                    : (authorities instanceof SequencedSet<GrantedAuthority> s)
                            ? Collections.unmodifiableSequencedSet(s)
                            : Collections.unmodifiableSequencedSet(new LinkedHashSet<>(authorities));
            return self();
        }

        /**
         * Makes attributes immutable.
         *
         * @param attributes attributes
         * @return this builder instance
         */
        public B attributes(Map<String, Object> attributes) {
            this.attributes = (attributes == null)
                    ? null
                    : Collections.unmodifiableMap(attributes);
            return self();
        }

    }

}
