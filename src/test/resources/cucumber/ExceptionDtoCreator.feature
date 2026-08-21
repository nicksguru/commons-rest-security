Feature: Exception DTO creator
  Creates exception DTOs while setting the HTTP response status and additional response headers

  Scenario: Valid error code sets response status from the HTTP status mapper
    Given a cause exception of type RuntimeException with message "boom"
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 404
    And the returned DTO should be the same object as the supplier's DTO
    And the log context should contain response status 404
    And the error message consumer should not be invoked

  Scenario Outline: Error codes are mapped to HTTP statuses and routed to a matching log level
    Given a cause exception of type RuntimeException with message "boom"
    And an error DTO with error code "<errorCode>"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be <status>
    And the log context should contain response status <status>
    And the error message consumer should be invoked: <consumerInvoked>
    Examples:
      | errorCode          | status | consumerInvoked |
      | VALIDATION_FAILED  | 400    | false           |
      | ENTITY_NOT_FOUND   | 404    | false           |
      | SUCCESS            | 200    | false           |
      | REDIRECT           | 302    | false           |
      | INTERNAL_ERROR     | 500    | true            |
      | SERVICE_UNAVAILABLE| 503    | true            |

  Scenario: 5xx errors pass the DTO and the cause to the error message consumer
    Given a cause exception of type RuntimeException with message "boom"
    And an error DTO with error code "INTERNAL_ERROR"
    When the exception DTO is created and HTTP status is set
    Then the error message consumer should be invoked once with a message containing the DTO and the cause

  Scenario: Cause wrapped in InvocationTargetException is unwrapped
    Given a business exception with an additional response header "X-Custom" and value "custom-value"
    And the cause is wrapped in an InvocationTargetException
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 404
    And the response should contain header "x-custom" with value "custom-value"
    And the error message consumer should not be invoked

  Scenario Outline: Valid additional response headers are sanitized and set on the response
    Given a business exception with an additional response header "<name>" and value "<value>"
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response should contain header "<expectedName>" with value "<expectedValue>"
    Examples:
      | name       | value           | expectedName | expectedValue |
      | X-Rate-Limit | 42            | x-rate-limit | 42            |
      | X-Custom   | line1\r\nline2  | x-custom     | line1line2    |
      | X-Token    | a\0b            | x-token      | ab            |
      | X-Cu\rstom | value           | x-custom     | value         |

  Scenario Outline: Invalid additional response headers are ignored
    Given a business exception with an additional response header "<name>" and value "<value>"
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 404
    And the response should contain no additional headers
    Examples:
      | name  | value |
      |       | value |
      | \r\n  | value |
      | \0    | value |
      | X-Empty |      |
      | X-CrLf | \r\n |
      | X-Nul  | \0   |

  Scenario: Whitespace-only header name is ignored
    Given a business exception with an additional response header " " and value "value"
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then the response should contain no additional headers

  Scenario: Whitespace-only header value is ignored
    Given a business exception with an additional response header "X-Custom" and value " "
    And an error DTO with error code "ENTITY_NOT_FOUND"
    When the exception DTO is created and HTTP status is set
    Then the response should contain no additional headers

  Scenario: Business exception without additional response headers
    Given a business exception without additional response headers
    And an error DTO with error code "INTERNAL_ERROR"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 500
    And the response should contain no additional headers

  Scenario: Unknown error code is passed to the mapper as null
    Given a cause exception of type RuntimeException with message "boom"
    And an error DTO with error code "NO_SUCH_CODE"
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 500
    And the HTTP status mapper should be invoked with a null error code
    And the error message consumer should be invoked with a message containing "NO_SUCH_CODE"

  Scenario: Missing error code is passed to the mapper as null
    Given a cause exception of type RuntimeException with message "boom"
    And an error DTO without an error code
    When the exception DTO is created and HTTP status is set
    Then no exception should be thrown
    And the response HTTP status should be 500
    And the HTTP status mapper should be invoked with a null error code
