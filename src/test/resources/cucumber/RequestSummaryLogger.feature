#@disabled
Feature: Request Summary Logger

  Background:
    Given request statistics are configured with slow threshold of 1000 milliseconds

  Scenario Outline: Request logging with different HTTP status codes and durations
    Given a request URI "<requestUri>"
    And an HTTP response with status code <statusCode>
    And a request duration of <durationMs> milliseconds
    When the request summary logger processes the request
    And the response should contain elapsed time header with value "<durationMs>"
    And the log context should contain response status "<statusCode>"
    And the log context should contain elapsed time "<durationMs>"
    And the request should be logged at "<logLevel>" level
    And the log message should contain slow marker: <slowMarker>
    Examples:
      | requestUri    | statusCode | durationMs | logLevel | slowMarker |
      | /api/users    | 200        | 500        | INFO     | false      |
      | /api/users    | 200        | 1500       | WARN     | true       |
      | /api/orders   | 404        | 300        | WARN     | false      |
      | /api/orders   | 404        | 1200       | WARN     | true       |
      | /api/internal | 500        | 800        | ERROR    | false      |
      | /api/internal | 500        | 1100       | ERROR    | true       |
      | /api/custom   | 600        | 400        | INFO     | false      |
      | /api/custom   | 600        | 1300       | WARN     | true       |

  Scenario: Request with null URI
    Given a null request URI
    And an HTTP response with status code 404
    And a request duration of 500 milliseconds
    When the request summary logger processes the request
    Then the log message should contain status code "404"
    And the request should be logged at "WARN" level

  Scenario: Request with custom HTTP status code
    Given a request URI "/api/custom"
    And an HTTP response with status code 999
    And a request duration of 300 milliseconds
    When the request summary logger processes the request
    Then the log message should contain status code "999"
    And the request should be logged at "INFO" level

  Scenario: Slow threshold disabled
    Given request statistics are configured with no slow threshold
    And a request URI "/api/test"
    And an HTTP response with status code 200
    And a request duration of 2000 milliseconds
    When the request summary logger processes the request
    Then the request should be logged at "INFO" level
    And the log message should contain slow marker: false

  Scenario: JVM memory information is logged
    Given a request URI "/api/memory"
    And an HTTP response with status code 200
    And a request duration of 100 milliseconds
    When the request summary logger processes the request
    Then the log context should contain RAM free MB
    And the log context should contain RAM max MB

  Scenario: Trace ID is included in response headers
    Given a request URI "/api/trace"
    And an HTTP response with status code 200
    And a request duration of 200 milliseconds
    And a trace ID "test-trace-123" is present
    When the request summary logger processes the request
    Then the response should contain trace ID header with value "test-trace-123"

  Scenario: Logger detector caching behavior
    Given a request URI "/api/cache"
    And an HTTP response with status code 200
    And a request duration of 500 milliseconds
    When the request summary logger processes the request multiple times
    Then the same logger should be returned for identical parameters
