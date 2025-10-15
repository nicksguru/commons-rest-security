#@disabled
Feature: Restrict JWT Audience
  JWT audience restriction validates AZP/AUD claims and throws BadJwtException for unauthorized audiences

  Scenario: JWT audience restriction allows any audience when restriction set is empty
    Given a JWT audience restriction step with empty allowed audiences
    And a JWT token with audience "unauthorized-app"
    When the JWT audience restriction is applied
    Then no exception should be thrown
    And the user principal should be returned unchanged after JWT audience restriction

  Scenario Outline: JWT audience restriction validates against allowed audiences
    Given allowed JWT audiences "<allowedAudiences>"
    And a JWT token with audience "<tokenAudience>"
    When the JWT audience restriction is applied
    Then the JWT audience restriction result should be "<expectedResult>"
    Examples:
      | allowedAudiences | tokenAudience | expectedResult  |
      | app1,app2        | app1          | success         |
      | app1,app2        | app2          | success         |
      | app1,app2        | app1,app3     | success         |
      | app1,app2        | app3          | BadJwtException |
      | app1,app2        | app3,app4     | BadJwtException |
      | my-app           | my-app        | success         |
      | my-app           | other-app     | BadJwtException |

  Scenario Outline: JWT audience restriction validates against AZP claim when available
    Given allowed JWT audiences "<allowedAudiences>"
    And a JWT token with AZP claim "<azpClaim>" and AUD claim "<audClaim>"
    When the JWT audience restriction is applied
    Then the JWT audience restriction result should be "<expectedResult>"
    Examples:
      | allowedAudiences | azpClaim | audClaim | expectedResult  |
      | app1,app2        | app1     | app3     | success         |
      | app1,app2        | app3     | app1     | BadJwtException |
      | app1,app2        | app1     |          | success         |
      | app1,app2        |          | app1     | success         |

  Scenario Outline: JWT audience restriction handles multiple audience values
    Given allowed JWT audiences "<allowedAudiences>"
    And a JWT token with multiple audiences "<tokenAudiences>"
    When the JWT audience restriction is applied
    Then the JWT audience restriction result should be "<expectedResult>"
    Examples:
      | allowedAudiences | tokenAudiences | expectedResult  |
      | app1,app2        | app1,app3,app4 | success         |
      | app1,app2        | app3,app4,app5 | BadJwtException |
      | app1             | app1,app2,app3 | success         |

  Scenario: JWT audience restriction preserves user principal when validation passes
    Given allowed JWT audiences "my-app"
    And a JWT token with audience "my-app"
    And an existing user principal with username "testuser" for JWT audience restriction
    When the JWT audience restriction is applied
    Then no exception should be thrown
    And the user principal should be returned unchanged after JWT audience restriction

  Scenario: JWT audience restriction works with null user principal
    Given allowed JWT audiences "my-app"
    And a JWT token with audience "my-app"
    And no existing user principal for JWT audience restriction
    When the JWT audience restriction is applied
    Then no exception should be thrown
    And the user principal should be null after audience restriction
