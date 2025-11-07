#@disabled
Feature: Reject Unsigned JWT
  JWT signature algorithm validation rejects unsigned tokens and allows signed tokens

  Scenario Outline: JWT with valid signature algorithm is accepted
    Given a reject unsigned JWT step
    And a JWT token with signature algorithm "<algorithm>"
    And an existing user principal with username "<username>" for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then no exception should be thrown
    And the user principal should be returned with username "<username>" after signature algorithm validation
    Examples:
      | algorithm | username |
      | RS256     | testuser |
      | HS256     | admin    |
      | ES256     | guest    |
      | PS256     | manager  |
      | RS384     | operator |
      | HS384     | viewer   |
      | ES384     | editor   |
      | PS384     | auditor  |
      | RS512     | analyst  |
      | HS512     | reporter |

  Scenario Outline: JWT with unsigned algorithm is rejected
    Given a reject unsigned JWT step
    And a JWT token with signature algorithm "<algorithm>"
    And an existing user principal with username "testuser" for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then the exception should be of type "BadJwtException"
    And the exception message should contain "Unencrypted JWT not allowed"
    Examples:
      | algorithm |
      | none      |
      | NONE      |
      | None      |
      | NoNe      |

  Scenario: JWT with missing signature algorithm header is rejected
    Given a reject unsigned JWT step
    And a JWT token with missing signature algorithm header
    And an existing user principal with username "testuser" for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then the exception should be of type "BadJwtException"
    And the exception message should contain "Unencrypted JWT not allowed"

  Scenario: JWT with null signature algorithm header is rejected
    Given a reject unsigned JWT step
    And a JWT token with null signature algorithm header
    And an existing user principal with username "testuser" for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then the exception should be of type "BadJwtException"
    And the exception message should contain "Unencrypted JWT not allowed"

  Scenario: JWT validation with null user principal is accepted for valid algorithm
    Given a reject unsigned JWT step
    And a JWT token with signature algorithm "RS256"
    And no existing user principal for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then no exception should be thrown
    And the user principal should be null after signature algorithm validation

  Scenario: JWT validation preserves user principal for valid algorithm
    Given a reject unsigned JWT step
    And a JWT token with signature algorithm "HS256"
    And an existing user principal with username "preservetest"
    When the reject unsigned JWT step is applied
    Then no exception should be thrown
    And the user principal should be returned with username "preservetest" after signature algorithm validation

  Scenario Outline: JWT with edge case signature algorithms
    Given a reject unsigned JWT step
    And a JWT token with signature algorithm "<algorithm>"
    And an existing user principal with username "testuser" for JWT signature algorithm validation
    When the reject unsigned JWT step is applied
    Then the JWT signature algorithm validation result should be "<expectedResult>"
    Examples:
      | algorithm | expectedResult  |
      |           | BadJwtException |
      | none      | BadJwtException |
      | INVALID   | success         |
      | rs256     | success         |
      | hs256     | success         |
      | 123       | success         |
      | @#$       | success         |
