package guru.nicks.commons.auth.domain;

import jakarta.annotation.Nonnull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.FieldDefaults;
import lombok.experimental.FieldNameConstants;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Enhanced user principal that combines Spring Security's {@link UserDetails} and OAuth2's
 * {@link OAuth2AuthenticatedPrincipal} with OpenID Connect user profile information.
 * <p>
 * This class provides a comprehensive representation of an authenticated user, supporting both traditional
 * username/password authentication and OAuth2 / OpenID Connect flows. Objects of this class are immutable.
 * <p>
 * WARNING: {@link #equals(Object)} and {@link #hashCode()} methods are implemented in {@link User} class and consider
 * the {@link #getUsername() username} only!
 *
 * @see UserDetails
 * @see OAuth2AuthenticatedPrincipal
 * @see OpenIdUserProfile
 */
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@FieldNameConstants
@ToString(callSuper = true)
public class CommonsUserPrincipal<R extends Enum<R>>
        extends User
        implements OpenIdUserProfile<R>, OAuth2AuthenticatedPrincipal {

    @Getter(onMethod_ = @Override)
    String id;

    @Getter(onMethod_ = @Override)
    String email;

    @Getter(onMethod_ = @Override)
    boolean emailVerified;

    @Getter
    JwtProvider jwtProvider;

    @Getter(onMethod_ = @Override)
    SortedSet<R> roles;

    @Getter(onMethod_ = @Override)
    String languageCode;

    @Getter(onMethod_ = @Override)
    String firstName;

    @Getter(onMethod_ = @Override)
    String lastName;

    @Getter(onMethod_ = @Override)
    String fullName;

    @Getter(onMethod_ = @Override)
    String pictureLink;

    /**
     * Usually JWT claims.
     */
    @Getter(onMethod_ = @Override)
    Map<String, Object> attributes;

    /**
     * Constructor. Prefer defining a builder in subclasses instead (this class has no builder because it's generic -
     * subclasses would need to redefine the return values anyway). The builder name should be something like
     * {@code newBuilder} because parent class already has {@link User#builder()}.
     * <p>
     * NOTE: the {@link #getPassword() password} becomes {@code null} upon successful authentication because
     * {@link ProviderManager} calls {@link User#eraseCredentials()}.
     *
     * @param username      username (non-null because parent constructor requires that)
     * @param password      password (non-null because parent constructor requires that)
     * @param roles         user roles (will be sorted, for predictable iteration order)
     * @param attributes    arbitrary attributes, such as JWT claims
     * @param id            user ID (under the hood, this can for example be a UUID, but as a string anyway)
     * @param email         email address
     * @param emailVerified {@code true} if email address has been verified
     * @param jwtProvider   foreign JWT provider ({@code null} for local users)
     * @param languageCode  2-letter ISO code, such as 'en'
     * @param firstName     first name
     * @param lastName      last name
     * @param fullName      full name (not necessarily first + last)
     * @param pictureLink   link to profile picture
     */
    @SuppressWarnings("java:S107") // allow more than 7 parameters
    public CommonsUserPrincipal(String username, String password,
            Collection<R> roles, Map<String, Object> attributes,
            String id, String email, boolean emailVerified,
            JwtProvider jwtProvider, String languageCode,
            String firstName, String lastName, String fullName,
            String pictureLink) {
        super(username,
                // parent class rejects null passwords, but accepts empty ones
                (password == null) ? "" : password,
                (roles == null)
                        ? AuthorityUtils.NO_AUTHORITIES
                        : AuthorityUtils.createAuthorityList(roles.stream()
                                .map(R::name)
                                .sorted()
                                .toArray(String[]::new)));

        this.roles = (roles == null)
                ? Collections.emptySortedSet()
                : Collections.unmodifiableSortedSet(new TreeSet<>(roles));

        // WARNING: don't call Map.copyOf - it rejects null keys and values, which may be the case (esp. null values),
        // therefore this map is not sorted (TreeSet forbids nulls), but the iteration order is nevertheless constant
        this.attributes = (attributes == null)
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));

        this.id = id;
        this.email = email;
        this.emailVerified = emailVerified;

        this.jwtProvider = jwtProvider;
        this.languageCode = languageCode;

        this.firstName = firstName;
        this.lastName = lastName;
        this.fullName = fullName;
        this.pictureLink = pictureLink;
    }

    /**
     * Copy constructor.
     *
     * @param source object to copy properties from
     */
    public CommonsUserPrincipal(@Nonnull @NonNull CommonsUserPrincipal<R> source) {
        this(source.getUsername(), source.getPassword(),
                source.getRoles(), source.getAttributes(),
                source.getId(), source.getEmail(), source.isEmailVerified(),
                source.getJwtProvider(), source.getLanguageCode(),
                source.getFirstName(), source.getLastName(), source.getFullName(),
                source.getPictureLink());
    }

    @Override
    public String getName() {
        return getUsername();
    }

    /**
     * @return {@code true} if {@link #getJwtProvider()} is not {@code null}
     */
    public boolean isForeignJwt() {
        return getJwtProvider() != null;
    }

}
