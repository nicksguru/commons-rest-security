package guru.nicks.commons.auth.domain;

import guru.nicks.commons.utils.crypto.ChecksumUtils;

import lombok.Builder;
import lombok.Value;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * User profile subset containing Open ID data - typically stored in JWT by auth providers. Contains some of the
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">standard claims</a>.
 *
 * @param <R> use role type
 */
public interface OpenIdUserProfile<R extends Comparable<R>> extends OpenIdConnectData {

    /**
     * This is a local (not OpenID) field actually.
     *
     * @return user roles
     */
    Set<R> getRoles();

    /**
     * Extracts only fields belonging to {@link OpenIdUserProfile}. Needed to limit the fields that take part in things
     * like checksum computation.
     *
     * @return {@link OpenIdUserProfile} instance with no additional fields
     */
    default Impl<R> reduceToBareOpenIdUserProfile() {
        return new Impl<>(this);
    }

    /**
     * Implementation for reducing other objects that implement {@link OpenIdUserProfile} to that interface's scope .
     * Needed for compact JSON serialization (to exclude additional fields) and limiting checksum computation to such
     * fields only.
     * <p>
     * WARNING: this class must be final to avoid mentioning any extra fields in JSON representation which is a source
     * for checksum computation.
     *
     */
    @Value
    @Builder(toBuilder = true)
    class Impl<R extends Comparable<R>> implements OpenIdUserProfile<R> {

        String id;
        String username;
        String languageCode;

        String email;
        boolean emailVerified;

        String firstName;
        String lastName;
        String fullName;

        String pictureLink;
        SortedSet<R> roles;

        // Constructor must be annotated with @Default (in any package) for MapStruct to prefer it over the copy
        // constructor. Lombok can't be used because '@AllArgsConstructor(onConstructor = @Default)' makes Javadoc
        // plugin crash.
        @Default
        public Impl(String id, String username, String languageCode,
                String email, boolean emailVerified,
                String firstName, String lastName, String fullName,
                String pictureLink, Set<R> roles) {
            this.id = id;
            this.username = username;
            this.languageCode = languageCode;

            this.email = email;
            this.emailVerified = emailVerified;

            this.firstName = firstName;
            this.lastName = lastName;
            this.fullName = fullName;

            this.pictureLink = pictureLink;

            // ensure consistent element order and non-nullness for checksum computation
            var tmpRoles = Optional.ofNullable(roles)
                    .map(TreeSet::new)
                    .orElseGet(TreeSet::new);
            this.roles = Collections.unmodifiableSortedSet(tmpRoles);
        }

        public Impl(OpenIdUserProfile<R> source) {
            id = source.getId();
            username = source.getUsername();
            languageCode = source.getLanguageCode();

            email = source.getEmail();
            emailVerified = source.isEmailVerified();

            firstName = source.getFirstName();
            lastName = source.getLastName();
            fullName = source.getFullName();

            pictureLink = source.getPictureLink();

            // ensure consistent element order and non-nullness for checksum computation
            var tmpRoles = Optional.ofNullable(source.getRoles())
                    .map(TreeSet::new)
                    .orElseGet(TreeSet::new);
            roles = Collections.unmodifiableSortedSet(tmpRoles);
        }

        /**
         * Encompasses only fields belonging to this class (which is final).
         *
         * @return checksum
         * @see ChecksumUtils#computeJsonChecksumSecure(Object)
         */
        public String computeChecksumSecure() {
            return ChecksumUtils.computeJsonChecksumSecure(this);
        }

        /**
         * Encompasses only fields belonging to this class (which is final).
         *
         * @return checksum
         * @see ChecksumUtils#computeJsonChecksumFast(Object)
         */
        public String computeChecksumFast() {
            return ChecksumUtils.computeJsonChecksumFast(this);
        }

        @Target(ElementType.CONSTRUCTOR)
        @Retention(RetentionPolicy.CLASS)
        public @interface Default {
        }

    }

}
