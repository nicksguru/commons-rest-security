package guru.nicks.commons.cucumber;

import guru.nicks.commons.auth.domain.OpenIdUserProfile;

import io.cucumber.java.DataTableType;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;

/**
 * Step definitions for testing {@link OpenIdUserProfile}.
 */
public class OpenIdUserProfileSteps {

    private OpenIdUserProfile.Impl<String> profile;
    private OpenIdUserProfile.Impl<String> reducedProfile;
    private OpenIdUserProfile.Impl<String> copyProfile;

    private String computedChecksum;
    private String secondChecksum;

    private OpenIdUserProfile<String> sourceProfile;
    private OpenIdUserProfile<String> secondSourceProfile;

    @DataTableType
    public OpenIdUserProfileData createOpenIdUserProfileData(Map<String, String> row) {
        var data = new OpenIdUserProfileData();
        data.setId(StringUtils.stripToNull(row.get("id")));
        data.setUsername(StringUtils.stripToNull(row.get("username")));
        data.setLanguageCode(StringUtils.stripToNull(row.get("languageCode")));

        data.setEmail(StringUtils.stripToNull(row.get("email")));
        data.setEmailVerified(Boolean.parseBoolean(row.get("emailVerified")));

        data.setFirstName(StringUtils.stripToNull(row.get("firstName")));
        data.setLastName(StringUtils.stripToNull(row.get("lastName")));
        data.setFullName(StringUtils.stripToNull(row.get("fullName")));

        data.setPictureLink(StringUtils.stripToNull(row.get("pictureLink")));
        data.setRoles(parseRoles(row.get("roles")));
        return data;
    }

    @Given("user profile data is provided:")
    public void userProfileDataIsProvided(List<OpenIdUserProfileData> dataList) {
        var data = dataList.getFirst();
        sourceProfile = createProfileFromData(data);
    }

    @Given("second user profile data is provided:")
    public void secondUserProfileDataIsProvided(List<OpenIdUserProfileData> dataList) {
        var data = dataList.getFirst();
        secondSourceProfile = createProfileFromData(data);
    }

    @Given("user profile with roles {string}")
    public void userProfileWithRoles(String roles) {
        var data = new OpenIdUserProfileData();
        data.setRoles(parseRoles(roles));
        sourceProfile = createProfileFromData(data);
    }

    @Given("user profile is created with all null fields")
    public void userProfileIsCreatedWithAllNullFields() {
        var data = new OpenIdUserProfileData();
        sourceProfile = createProfileFromData(data);
    }

    @When("user profile is created using builder")
    public void userProfileIsCreatedUsingBuilder() {
        var impl = (OpenIdUserProfile.Impl<String>) sourceProfile;
        this.profile = spy(OpenIdUserProfile.Impl.<String>builder()
                .id(impl.getId())
                .username(impl.getUsername())
                .languageCode(impl.getLanguageCode())
                //
                .email(impl.getEmail())
                .emailVerified(impl.isEmailVerified())
                //
                .firstName(impl.getFirstName())
                .lastName(impl.getLastName())
                .fullName(impl.getFullName())
                //
                .pictureLink(impl.getPictureLink())
                .roles(impl.getRoles())
                .build());
    }

    @When("profile is reduced from source")
    public void profileIsReducedFromSource() {
        reducedProfile = sourceProfile.reduceToBareOpenIdUserProfile();
    }

    @When("checksum is computed")
    public void checksumIsComputed() {
        computedChecksum = sourceProfile
                .reduceToBareOpenIdUserProfile()
                .computeChecksumSecure();
    }

    @When("secure checksum is computed")
    public void secureChecksumIsComputed() {
        computedChecksum = sourceProfile
                .reduceToBareOpenIdUserProfile()
                .computeChecksumSecure();
    }

    @When("fast checksum is computed")
    public void fastChecksumIsComputed() {
        computedChecksum = sourceProfile
                .reduceToBareOpenIdUserProfile()
                .computeChecksumFast();
    }

    @When("checksums are computed for both profiles")
    public void checksumsAreComputedForBothProfiles() {
        computedChecksum = sourceProfile
                .reduceToBareOpenIdUserProfile()
                .computeChecksumSecure();
        secondChecksum = secondSourceProfile
                .reduceToBareOpenIdUserProfile()
                .computeChecksumSecure();
    }

    @When("second checksum is computed")
    public void secondChecksumIsComputed() {
        secondChecksum = reducedProfile.computeChecksumSecure();
    }

    @When("profile is copied using toBuilder")
    public void profileIsCopiedUsingToBuilder() {
        var impl = (OpenIdUserProfile.Impl<String>) sourceProfile;
        copyProfile = impl.toBuilder().build();
    }

    @When("profile is created")
    public void profileIsCreated() {
        var impl = (OpenIdUserProfile.Impl<String>) sourceProfile;
        profile = OpenIdUserProfile.Impl.<String>builder()
                .id(impl.getId())
                .username(impl.getUsername())
                .languageCode(impl.getLanguageCode())
                //
                .email(impl.getEmail())
                .emailVerified(impl.isEmailVerified())
                //
                .firstName(impl.getFirstName())
                .lastName(impl.getLastName())
                .fullName(impl.getFullName())
                //
                .pictureLink(impl.getPictureLink())
                .roles(impl.getRoles())
                .build();
    }

    @When("profile is validated")
    public void profileIsValidated() {
        profile = sourceProfile.reduceToBareOpenIdUserProfile();
    }

    @Then("profile fields should match:")
    public void profileFieldsShouldMatch(List<OpenIdUserProfileData> expectedDataList) {
        var expected = expectedDataList.getFirst();
        assertThat(profile.getId())
                .as("profile id")
                .isEqualTo(expected.getId());
        assertThat(profile.getUsername())
                .as("profile username")
                .isEqualTo(expected.getUsername());
        assertThat(profile.getLanguageCode())
                .as("profile languageCode")
                .isEqualTo(expected.getLanguageCode());

        assertThat(profile.getEmail())
                .as("profile email")
                .isEqualTo(expected.getEmail());
        assertThat(profile.isEmailVerified())
                .as("profile emailVerified")
                .isEqualTo(expected.isEmailVerified());

        assertThat(profile.getFirstName())
                .as("profile firstName")
                .isEqualTo(expected.getFirstName());
        assertThat(profile.getLastName())
                .as("profile lastName")
                .isEqualTo(expected.getLastName());
        assertThat(profile.getFullName())
                .as("profile fullName")
                .isEqualTo(expected.getFullName());

        assertThat(profile.getPictureLink())
                .as("profile pictureLink")
                .isEqualTo(expected.getPictureLink());
        compareRolesForBuilder(profile.getRoles(), expected.getRoles(), "profile");
    }

    @Then("reduced profile fields should match:")
    public void reducedProfileFieldsShouldMatch(List<OpenIdUserProfileData> expectedDataList) {
        var expected = expectedDataList.getFirst();
        assertThat(reducedProfile.getId())
                .as("reducedProfile id")
                .isEqualTo(expected.getId());
        assertThat(reducedProfile.getUsername())
                .as("reducedProfile username")
                .isEqualTo(expected.getUsername());
        assertThat(reducedProfile.getLanguageCode())
                .as("reducedProfile languageCode")
                .isEqualTo(expected.getLanguageCode());

        assertThat(reducedProfile.getEmail())
                .as("reducedProfile email")
                .isEqualTo(expected.getEmail());
        assertThat(reducedProfile.isEmailVerified())
                .as("reducedProfile emailVerified")
                .isEqualTo(expected.isEmailVerified());

        assertThat(reducedProfile.getFirstName())
                .as("reducedProfile firstName")
                .isEqualTo(expected.getFirstName());
        assertThat(reducedProfile.getLastName())
                .as("reducedProfile lastName")
                .isEqualTo(expected.getLastName());
        assertThat(reducedProfile.getFullName())
                .as("reducedProfile fullName")
                .isEqualTo(expected.getFullName());

        assertThat(reducedProfile.getPictureLink())
                .as("reducedProfile pictureLink")
                .isEqualTo(expected.getPictureLink());
        compareRoles(reducedProfile.getRoles(), expected.getRoles(), "reducedProfile");
    }

    @Then("roles should be sorted")
    public void rolesShouldBeSorted() {
        var roles = (reducedProfile != null)
                ? reducedProfile.getRoles()
                : profile.getRoles();

        if (CollectionUtils.isNotEmpty(roles)) {
            var sortedRoles = new TreeSet<>(roles);
            assertThat(roles)
                    .as("roles should be sorted")
                    .isEqualTo(sortedRoles);
        }
    }

    @Then("checksum should be {string}")
    public void checksumShouldBe(String expectedChecksum) {
        assertThat(computedChecksum)
                .as("computedChecksum")
                .isEqualTo(expectedChecksum);
    }

    @Then("checksum should not be blank")
    public void checksumShouldNotBeBlank() {
        assertThat(computedChecksum)
                .as("computedChecksum")
                .isNotBlank();
    }

    @Then("checksums should be equal")
    public void checksumsShouldBeEqual() {
        assertThat(computedChecksum)
                .as("first checksum")
                .isNotBlank();
        assertThat(secondChecksum)
                .as("second checksum")
                .isNotBlank();
        assertThat(computedChecksum)
                .as("checksums should be equal")
                .isEqualTo(secondChecksum);
    }

    @Then("checksums should be different")
    public void checksumsShouldBeDifferent() {
        assertThat(computedChecksum)
                .as("first checksum")
                .isNotBlank();
        assertThat(secondChecksum)
                .as("second checksum")
                .isNotBlank();
        assertThat(computedChecksum)
                .as("checksums should be different")
                .isNotEqualTo(secondChecksum);
    }

    @Then("copy should equal original")
    public void copyShouldEqualOriginal() {
        assertThat(copyProfile)
                .as("copyProfile")
                .isEqualTo(sourceProfile);
    }

    @Then("roles should be empty")
    public void rolesShouldBeEmpty() {
        var roles = (profile != null)
                ? profile.getRoles()
                : reducedProfile.getRoles();

        if (roles == null) {
            assertThat(roles)
                    .as("profile roles")
                    .isNull();
        } else {
            assertThat(roles)
                    .as("profile roles")
                    .isEmpty();
        }
    }

    @Then("all fields should be null or default")
    public void allFieldsShouldBeNullOrDefault() {
        var profileToCheck = (profile != null)
                ? profile
                : reducedProfile;

        assertThat(profileToCheck.getId())
                .as("profile id")
                .isNull();
        assertThat(profileToCheck.getUsername())
                .as("profile username")
                .isNull();
        assertThat(profileToCheck.getLanguageCode())
                .as("profile languageCode")
                .isNull();

        assertThat(profileToCheck.getEmail())
                .as("profile email")
                .isNull();
        assertThat(profileToCheck.isEmailVerified())
                .as("profile emailVerified")
                .isFalse();
        assertThat(profileToCheck.getFirstName())
                .as("profile firstName")
                .isNull();
        assertThat(profileToCheck.getLastName())
                .as("profile lastName")
                .isNull();
        assertThat(profileToCheck.getFullName())
                .as("profile fullName")
                .isNull();

        assertThat(profileToCheck.getPictureLink())
                .as("profile pictureLink")
                .isNull();
    }

    private void compareRoles(Set<String> actual, Set<String> expected, String profileName) {
        if (CollectionUtils.isEmpty(expected)) {
            assertThat(actual)
                    .as(profileName + " roles")
                    .isNotNull();
            assertThat(actual)
                    .as(profileName + " roles")
                    .isEmpty();
        } else {
            assertThat(actual)
                    .as(profileName + " roles")
                    .isEqualTo(expected);
        }
    }

    private void compareRolesForBuilder(Set<String> actual, Set<String> expected, String profileName) {
        if (CollectionUtils.isEmpty(expected)) {
            // for builder-created profiles, roles can be null
            if (actual == null) {
                assertThat(actual)
                        .as(profileName + " roles")
                        .isNull();
            } else {
                assertThat(actual)
                        .as(profileName + " roles")
                        .isEmpty();
            }
        } else {
            assertThat(actual)
                    .as(profileName + " roles")
                    .isEqualTo(expected);
        }
    }

    private OpenIdUserProfile.Impl<String> createProfileFromData(OpenIdUserProfileData data) {
        return OpenIdUserProfile.Impl.<String>builder()
                .id(data.getId())
                .username(data.getUsername())
                .languageCode(data.getLanguageCode())
                //
                .email(data.getEmail())
                .emailVerified(data.isEmailVerified())
                //
                .firstName(data.getFirstName())
                .lastName(data.getLastName())
                .fullName(data.getFullName())
                //
                .pictureLink(data.getPictureLink())
                .roles(data.getRoles())
                .build();
    }

    private SortedSet<String> parseRoles(String rolesStr) {
        if (StringUtils.isBlank(rolesStr)) {
            return null;
        }

        return new TreeSet<>(Arrays.asList(rolesStr.split(",")))
                .stream()
                .map(StringUtils::stripToNull)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    @Getter
    @Setter
    public static class OpenIdUserProfileData {

        private String id;
        private String username;
        private String languageCode;

        private String email;
        private boolean emailVerified;

        private String firstName;
        private String lastName;
        private String fullName;

        private String pictureLink;
        private SortedSet<String> roles;

    }

}
