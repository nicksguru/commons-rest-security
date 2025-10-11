package guru.nicks.security.domain;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Value;
import lombok.experimental.NonFinal;
import lombok.extern.jackson.Jacksonized;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "cors")
@Validated
// immutability
@Value
@NonFinal // needed for CGLIB to bind property values (nested classes don't need this)
@Jacksonized
@Builder(toBuilder = true)
public class CorsProperties {

    boolean allowCredentials;

    List<String> originAllowList;
    List<String> allowHeaders;
    List<String> allowMethods;

    @NotNull
    Duration accessControlMaxAge;

}
