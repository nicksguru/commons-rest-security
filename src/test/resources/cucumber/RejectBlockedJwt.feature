#@disabled
Feature: Reject Blocked JWT
  JWT token blocking validation rejects blocked tokens and allows non-blocked tokens

  Scenario Outline: JWT token blocking validation with various token states
    Given a reject blocked JWT step with predicate returning <booleanValue>
    And a JWT token with value "<tokenValue>" for JWT block check
    And an existing user principal with username "<username>" for JWT block check
    When the reject blocked JWT step is applied
    Then the result should be "<expectedResult>"
    Examples:
      | booleanValue | tokenValue    | username | expectedResult |
      | true         | blocked-token | testuser | exception      |
      | false        | valid-token   | testuser | success        |
      | true         | expired-token | admin    | exception      |
      | false        | fresh-token   | admin    | success        |
      | true         | revoked-token | guest    | exception      |
      | false        | active-token  | guest    | success        |

  Scenario: JWT token validation preserves user principal when token is not blocked
    Given a reject blocked JWT step with predicate returning false
    And a JWT token with value "valid-token-123" for JWT block check
    And an existing user principal with username "preservetest" for JWT block check
    When the reject blocked JWT step is applied
    Then no exception should be thrown
    And the user principal should be returned with username "preservetest" after JWT block check

  Scenario: JWT token validation with null user principal when token is not blocked
    Given a reject blocked JWT step with predicate returning false
    And a JWT token with value "valid-token-456" for JWT block check
    And no existing user principal
    When the reject blocked JWT step is applied
    Then no exception should be thrown
    And the user principal should be null after JWT block check

  Scenario Outline: JWT token validation with different token formats
    Given a reject blocked JWT step with predicate that blocks tokens containing "<blockedPattern>"
    And a JWT token with value "<tokenValue>" for JWT block check
    And an existing user principal with username "testuser" for JWT block check
    When the reject blocked JWT step is applied
    Then the result should be "<expectedResult>"
    Examples:
      | blockedPattern | tokenValue           | expectedResult |
      | blocked        | valid-token          | success        |
      | blocked        | blocked-token        | exception      |
      | blocked        | token-blocked-suffix | exception      |
      | revoked        | active-token         | success        |
      | revoked        | revoked-token        | exception      |
      | expired        | fresh-token          | success        |
      | expired        | expired-token        | exception      |

  Scenario: JWT token validation with predicate that always blocks
    Given a reject blocked JWT step with predicate returning true
    And a JWT token with value "any-token" for JWT block check
    And an existing user principal with username "testuser" for JWT block check
    When the reject blocked JWT step is applied
    Then an exception should be thrown
    And the exception should be of type "AuthTokenBlockedException" after JWT block check

  Scenario: JWT token validation with predicate that never blocks
    Given a reject blocked JWT step with predicate returning false
    And a JWT token with value "any-token" for JWT block check
    And an existing user principal with username "testuser" for JWT block check
    When the reject blocked JWT step is applied
    Then no exception should be thrown
    And the user principal should be returned with username "testuser" after JWT block check

  Scenario Outline: JWT token validation with edge case token values
    Given a reject blocked JWT step with predicate that blocks empty or null tokens
    And a JWT token with value "<tokenValue>" for JWT block check
    And an existing user principal with username "testuser" for JWT block check
    When the reject blocked JWT step is applied
    Then the result should be "<expectedResult>"
    Examples:
      | tokenValue | expectedResult |
      |            | exception      |
      | valid      | success        |
      | token123   | success        |

  Scenario: JWT token validation verifies predicate is called with correct token value
    Given a reject blocked JWT step with spy predicate returning false
    And a JWT token with value "test-token-value" for JWT block check
    And an existing user principal with username "testuser" for JWT block check
    When the reject blocked JWT step is applied
    Then no exception should be thrown
    And the predicate should have been called with "test-token-value"
