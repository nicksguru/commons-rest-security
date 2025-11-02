package guru.nicks.auth.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;
import org.apache.commons.codec.digest.DigestUtils;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * User profile subset containing Open ID data - typically stored in JWT by auth providers. Contains some of the
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">standard claims</a>.
 *
 * @param <R> use role enum type
 */
public interface OpenIdUserProfile<R extends Enum<R>> extends OpenIdConnectData {

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
    @Jacksonized
    @Builder(toBuilder = true)
    class Impl<R extends Enum<R>> implements OpenIdUserProfile<R> {

        /**
         * Converter with predictable features crucial for consistent {@link Impl#computeChecksum() checksum}
         * computation. JSON keys are always sorted - to avoid checksum differences caused by random key order. Also,
         * dates are written as timestamps, for consistency. {@link ObjectMapper} bean is not used because it may or may
         * not be configured to sort keys.
         */
        private static final ObjectMapper KEY_SORTING_OBJECT_MAPPER = new ObjectMapper()
                // sort keys in JSON to render unsorted maps, such as HashMap, in consistent order
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                // process Java 8 dates
                .registerModule(new JavaTimeModule());

        String id;
        String username;
        String languageCode;

        String email;
        boolean emailVerified;

        String firstName;
        String lastName;
        String fullName;

        String pictureLink;
        Set<R> roles;

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
            this.roles = roles;
        }

        public Impl(OpenIdUserProfile<R> parent) {
            id = parent.getId();
            username = parent.getUsername();
            languageCode = parent.getLanguageCode();

            email = parent.getEmail();
            emailVerified = parent.isEmailVerified();

            firstName = parent.getFirstName();
            lastName = parent.getLastName();
            fullName = parent.getFullName();

            pictureLink = parent.getPictureLink();

            // ensure consistent element order for checksum computation
            roles = Optional.ofNullable(parent.getRoles())
                    .map(TreeSet::new)
                    .orElseGet(TreeSet::new);
        }

        /**
         * Encompasses only fields belonging to this class (which is final).
         *
         * @return checksum
         */
        public String computeChecksum() {
            String json;

            try {
                json = KEY_SORTING_OBJECT_MAPPER.writeValueAsString(this);
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Failed to serialize to JSON: " + e.getMessage(), e);
            }

            return DigestUtils.sha256Hex(json);
        }


        @Target(ElementType.CONSTRUCTOR)
        @Retention(RetentionPolicy.CLASS)
        public @interface Default {
        }

    }

}
