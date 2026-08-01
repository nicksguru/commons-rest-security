@security #@disabled
Feature: CommonsUserPrincipal

  Scenario: Create a user principal with all fields
    Given a username "john.doe"
    And a password "secret123"
    And roles:
      | ROLE_USER  |
      | ROLE_ADMIN |
    And attributes:
      | key    | value  |
      | claim1 | value1 |
      | claim2 | value2 |
    And user ID "12345"
    And email "john@example.com"
    And email verified is true
    And JWT provider is GOOGLE
    And language code "en"
    And first name "John"
    And last name "Doe"
    And full name "John Doe"
    And picture link "https://example.com/pic.jpg"
    When a user principal is created
    Then the user principal username should be "john.doe"
    And the user principal password should be "secret123"
    And the user principal roles should be:
      | ROLE_ADMIN |
      | ROLE_USER  |
    And the user principal attributes should be:
      | key    | value  |
      | claim1 | value1 |
      | claim2 | value2 |
    And the user principal ID should be "12345"
    And the user principal email should be "john@example.com"
    And the user principal email verified should be true
    And the user principal JWT provider should be GOOGLE
    And the user principal language code should be "en"
    And the user principal first name should be "John"
    And the user principal last name should be "Doe"
    And the user principal full name should be "John Doe"
    And the user principal picture link should be "https://example.com/pic.jpg"
    And the user principal should be a foreign JWT

  Scenario: Create a user principal with minimal fields
    Given a username "jane.doe"
    And a password null
    And no roles
    And no attributes
    And user ID "67890"
    And email "jane@example.com"
    And email verified is false
    And JWT provider is null
    And language code null
    And first name null
    And last name null
    And full name null
    And picture link null
    When a user principal is created
    Then the user principal username should be "jane.doe"
    And the user principal password should be null
    And the user principal roles should be empty
    And the user principal authorities should be empty
    And the user principal attributes should be empty
    And the user principal ID should be "67890"
    And the user principal email should be "jane@example.com"
    And the user principal email verified should be false
    And the user principal JWT provider should be null
    And the user principal language code should be null
    And the user principal first name should be null
    And the user principal last name should be null
    And the user principal full name should be null
    And the user principal picture link should be null
    And the user principal should not be a foreign JWT

  Scenario: Create a user principal using copy constructor
    Given a username "original.user"
    And a password "originalPass"
    And roles:
      | ROLE_MODERATOR |
    And attributes:
      | key        | value       |
      | customAttr | customValue |
    And user ID "11111"
    And email "original@example.com"
    And email verified is true
    And JWT provider is GOOGLE
    And language code "de"
    And first name "Original"
    And last name "User"
    And full name "Original User"
    And picture link "https://example.com/original.jpg"
    When a user principal is created
    And a copy is made using the copy constructor
    Then the copied user principal username should be "original.user"
    And the copied user principal password should be "originalPass"
    And the copied user principal roles should be:
      | ROLE_MODERATOR |
    And the copied user principal attributes should be:
      | key        | value       |
      | customAttr | customValue |
    And the copied user principal ID should be "11111"
    And the copied user principal email should be "original@example.com"
    And the copied user principal email verified should be true
    And the copied user principal JWT provider should be GOOGLE
    And the copied user principal language code should be "de"
    And the copied user principal first name should be "Original"
    And the copied user principal last name should be "User"
    And the copied user principal full name should be "Original User"
    And the copied user principal picture link should be "https://example.com/original.jpg"
    And the copied user principal should be a foreign JWT

  Scenario: Verify getName returns username
    Given a username "nameuser"
    And a password "namepass"
    And no roles
    And no attributes
    And user ID "66666"
    And email "nameuser@example.com"
    And email verified is true
    And JWT provider is null
    And language code "ro"
    And first name "Name"
    And last name "User"
    And full name "Name User"
    And picture link "https://example.com/name.jpg"
    When a user principal is created
    Then the user principal name should be "nameuser"

  Scenario: Verify authorities are created from roles
    Given a username "auth.user"
    And a password "authpass"
    And roles:
      | ROLE_USER      |
      | ROLE_ADMIN     |
      | ROLE_MODERATOR |
    And no attributes
    And user ID "77777"
    And email "auth@example.com"
    And email verified is true
    And JWT provider is GOOGLE
    And language code "zh"
    And first name "Auth"
    And last name "User"
    And full name "Auth User"
    And picture link "https://example.com/auth.jpg"
    When a user principal is created
    Then the user principal authorities should be:
      | ROLE_ADMIN     |
      | ROLE_MODERATOR |
      | ROLE_USER      |
    And the user principal should have authority "ROLE_ADMIN"
    And the user principal should have authority "ROLE_USER"
    And the user principal should not have authority "ROLE_SUPERADMIN"

  Scenario: Verify user principal is immutable
    Given a username "immutable.user"
    And a password "immutablepass"
    And roles:
      | ROLE_USER |
    And attributes:
      | key       | value |
      | immutable | value |
    And user ID "88888"
    And email "immutable@example.com"
    And email verified is true
    And JWT provider is GOOGLE
    And language code "ja"
    And first name "Immutable"
    And last name "User"
    And full name "Immutable User"
    And picture link "https://example.com/immutable.jpg"
    When a user principal is created
    Then the user principal roles should be immutable
    And the user principal attributes should be immutable
