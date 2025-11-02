package guru.nicks.auth.domain;

import lombok.Builder;
import lombok.ToString;
import lombok.Value;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.NonFinal;
import lombok.extern.jackson.Jacksonized;

@Value
@NonFinal
@Jacksonized
@Builder(toBuilder = true)
@FieldNameConstants
public class OAuth2Provider {

    /**
     * {@link #getId()} of the auth provider that generates project's private service-to-service JWTs
     */
    public static final String INTERNAL_PROVIDER_ID = "internal";

    String id;

    /**
     * {@code null} means JWT tokens aren't accepted from this provider
     */
    String jwksUrl;

    /**
     * {@code null} means JWT tokens aren't generated, only verified
     */
    String tokenUrl;

    String clientId;

    @ToString.Exclude
    String clientSecret;

}
