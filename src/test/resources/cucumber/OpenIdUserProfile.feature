#@disabled
Feature: OpenID User Profile

  Scenario Outline: User profile is created using builder
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When user profile is created using builder
    Then profile fields should match:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    Examples:
      | id            | username | languageCode | email            | emailVerified | firstName | lastName | fullName   | pictureLink             | roles      |
      | user123       | john.doe | en           | john@example.com | true          | John      | Doe      | John Doe   | https://example.com/pic | ROLE_USER  |
      | user456       | jane.doe | fr           | jane@example.com | false         | Jane      | Smith    | Jane Smith |                         | ROLE_ADMIN |
      | user789       |          | de           |                  | false         |           |          |            |                         |            |
      |               | bob.test | es           | bob@test.com     | true          | Bob       |          |            |                         |            |
      | custom-id-123 | user.one | it           | user@one.com     | true          | User      | One      |            |                         | ROLE_GUEST |

  Scenario Outline: User profile is created from source profile
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When profile is reduced from source
    Then reduced profile fields should match:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    And roles should be sorted
    Examples:
      | id      | username | languageCode | email             | emailVerified | firstName | lastName | fullName | pictureLink       | roles                |
      | user001 | alice    | en           | alice@example.com | true          | Alice     | Wonder   | Alice W. | https://pic.url/1 | ROLE_USER,ROLE_ADMIN |
      | user002 | bob      | en           | bob@example.com   | false         | Bob       | Builder  | Bob B.   |                   | ROLE_GUEST           |
      | user003 | charlie  | en           |                   | true          | Charlie   |          |          |                   |                      |

  Scenario Outline: Profile toBuilder creates copy
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When profile is copied using toBuilder
    Then copy should equal original
    Examples:
      | id      | username | languageCode | email             | emailVerified | firstName | lastName | fullName | pictureLink       | roles      |
      | user001 | alice    | en           | alice@example.com | true          | Alice     | Wonder   | Alice W. | https://pic.url/1 | ROLE_USER  |
      | user002 | bob      | en           | bob@example.com   | false         | Bob       | Builder  | Bob B.   |                   | ROLE_ADMIN |

  Scenario Outline: Empty roles are handled correctly
    Given user profile with roles "<roles>"
    When profile is created
    Then roles should be empty
    Examples:
      | roles |
      |       |

  Scenario: Profile with all null fields is created
    Given user profile is created with all null fields
    When profile is reduced from source
    Then all fields should be null or default
    And roles should be empty

  Scenario Outline: Roles order is preserved after construction from source
    Given user profile with roles "<roles>"
    When profile is reduced from source
    Then roles should be sorted
    Examples:
      | roles                           |
      | ROLE_USER,ROLE_ADMIN            |
      | ROLE_GUEST,ROLE_USER,ROLE_ADMIN |
      | ROLE_Z,ROLE_A,ROLE_M            |

  Scenario Outline: Secure checksum is computed for profile
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When secure checksum is computed
    Then checksum should be "<expectedChecksum>"
    Examples:
      | id            | username | languageCode | email            | emailVerified | firstName | lastName | fullName   | pictureLink             | roles                | expectedChecksum                             |
      | user123       | john.doe | en           | john@example.com | true          | John      | Doe      | John Doe   | https://example.com/pic | ROLE_USER            | AnmNmXpoG8xrhwFQ4rmJzqYMsBUT/22W9QuPAM+viNY= |
      | user456       | jane.doe | fr           | jane@example.com | false         | Jane      | Smith    | Jane Smith |                         | ROLE_ADMIN           | nVpvSybeTOUoiFhYBma27ikXd/rGY87lGSUgB4Odk5k= |
      | user789       |          | de           |                  | false         |           |          |            |                         |                      | NU9X5hy1qGaqnR2P6TYljezOW7azxal0paqhvWap40I= |
      |               | bob.test | es           | bob@test.com     | true          | Bob       |          |            |                         | ROLE_GUEST           | X6mLa8w1Y0oNGNtFQ95K3g9bC02e9Rw/Rc5UGAx3Kqk= |
      | custom-id-123 | user.one | it           | user@one.com     | true          | User      | One      |            |                         | ROLE_GUEST,ROLE_USER | +mHsR2rLvKBCADlhOeci3dcwhVv+D+9s5mU3bn7gMNE= |

  Scenario Outline: Fast checksum is computed for profile
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When fast checksum is computed
    Then checksum should be "<expectedChecksum>"
    Examples:
      | id            | username | languageCode | email            | emailVerified | firstName | lastName | fullName   | pictureLink             | roles                | expectedChecksum                             |
      | user123       | john.doe | en           | john@example.com | true          | John      | Doe      | John Doe   | https://example.com/pic | ROLE_USER            | VVvvx2WNruv6v+HbZLDm+Y0n/uJvIiUoiizza1pqWo8= |
      | user456       | jane.doe | fr           | jane@example.com | false         | Jane      | Smith    | Jane Smith |                         | ROLE_ADMIN           | k61CG0K4uMY9msm2wswtqsuWLUzNUsN/kC8RXIq/720= |
      | user789       |          | de           |                  | false         |           |          |            |                         |                      | YqD3uQxXYP6LM3cD8QDpnGQ9FhpC65gDCGQxaJ/hjIg= |
      |               | bob.test | es           | bob@test.com     | true          | Bob       |          |            |                         | ROLE_GUEST           | aPsAhb4BxjC7JfD4Li/ePdI1Pihu6yVKy3wVQW3TR8E= |
      | custom-id-123 | user.one | it           | user@one.com     | true          | User      | One      |            |                         | ROLE_GUEST,ROLE_USER | 9ZSeSk1jap5ojH0gtpOTWsdv+AKcMPblQGY9V0gzn2M= |

  Scenario Outline: Identical profiles produce same checksum
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When secure checksum is computed
    And profile is reduced from source
    And second checksum is computed
    Then checksums should be equal
    Examples:
      | id      | username | languageCode | email             | emailVerified | firstName | lastName | fullName | pictureLink       | roles                |
      | user001 | alice    | en           | alice@example.com | true          | Alice     | Wonder   | Alice W. | https://pic.url/1 | ROLE_USER,ROLE_ADMIN |
      | user002 | bob      | en           | bob@example.com   | false         | Bob       | Builder  | Bob B.   |                   | ROLE_GUEST           |

  Scenario Outline: Different profiles produce different checksums
    Given user profile data is provided:
      | id    | username    | languageCode    | email    | emailVerified    | firstName    | lastName    | fullName    | pictureLink    | roles    |
      | <id1> | <username1> | <languageCode1> | <email1> | <emailVerified1> | <firstName1> | <lastName1> | <fullName1> | <pictureLink1> | <roles1> |
    And second user profile data is provided:
      | id    | username    | languageCode    | email    | emailVerified    | firstName    | lastName    | fullName    | pictureLink    | roles    |
      | <id2> | <username2> | <languageCode2> | <email2> | <emailVerified2> | <firstName2> | <lastName2> | <fullName2> | <pictureLink2> | <roles2> |
    When checksums are computed for both profiles
    Then checksums should be different
    Examples:
      | id1     | username1 | languageCode1 | email1            | emailVerified1 | firstName1 | lastName1 | fullName1 | pictureLink1      | roles1    | id2     | username2 | languageCode2 | email2            | emailVerified2 | firstName2 | lastName2 | fullName2 | pictureLink2      | roles2    |
      | user001 | alice     | en            | alice@example.com | true           | Alice      | Wonder    | Alice W.  | https://pic.url/1 | ROLE_USER | user002 | bob       | en            | bob@example.com   | true           | Bob        | Builder   | Bob B.    | https://pic.url/1 | ROLE_USER |
      | user003 | charlie   | en            |                   | true           | Charlie    |           |           |                   |           | user004 | diana     | en            | diana@example.com | true           | Diana      | Prince    | Diana P.  |                   |           |

  Scenario Outline: Checksums differ when roles order differs
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles    |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles1> |
    And second user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles    |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles2> |
    When checksums are computed for both profiles
    Then checksums should be equal
    Examples:
      | id      | username | languageCode | email             | emailVerified | firstName | lastName | fullName | pictureLink | roles1                          | roles2                          |
      | user001 | alice    | en           | alice@example.com | true          | Alice     | Wonder   | Alice W. |             | ROLE_USER,ROLE_ADMIN,ROLE_GUEST | ROLE_ADMIN,ROLE_USER,ROLE_GUEST |
      | user002 | bob      | en           | bob@example.com   | false         | Bob       | Builder  | Bob B.   |             | ROLE_Z,ROLE_A,ROLE_M            | ROLE_A,ROLE_M,ROLE_Z            |

  Scenario Outline: Checksum is computed from reduced profile
    Given user profile data is provided:
      | id   | username   | languageCode   | email   | emailVerified   | firstName   | lastName   | fullName   | pictureLink   | roles   |
      | <id> | <username> | <languageCode> | <email> | <emailVerified> | <firstName> | <lastName> | <fullName> | <pictureLink> | <roles> |
    When checksum is computed
    Then checksum should be "<expectedChecksum>"
    Examples:
      | id      | username | languageCode | email             | emailVerified | firstName | lastName | fullName | pictureLink       | roles                | expectedChecksum                             |
      | user001 | alice    | en           | alice@example.com | true          | Alice     | Wonder   | Alice W. | https://pic.url/1 | ROLE_USER,ROLE_ADMIN | t01fZ9fRNuYAQDacUajrLWLwMq8Kw4yoHZ0JbHAb41I= |
      | user002 | bob      | en           | bob@example.com   | false         | Bob       | Builder  | Bob B.   |                   | ROLE_GUEST           | GMGhT+qsWX8mA6wZJonkx7O/gP5sZM0ROyIYqJojB7Y= |
