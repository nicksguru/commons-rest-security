#@disabled
Feature: Logger Detector

  Scenario Outline: Logger detection for different HTTP status codes (including edge cases) and request speeds
    Given an HTTP status code of <statusCode>
    And the request is slow: <requestIsSlow>
    When the logger detector determines the appropriate logger
    Then the detected logger should be at "<expectedLogLevel>" level
    Examples:
      | statusCode | requestIsSlow | expectedLogLevel |
      | -1         | true          | WARN             |
      | 0          | false         | INFO             |
      | 100        | true          | WARN             |
      | 200        | false         | INFO             |
      | 200        | true          | WARN             |
      | 201        | false         | INFO             |
      | 201        | true          | WARN             |
      | 399        | false         | INFO             |
      | 399        | true          | WARN             |
      | 400        | false         | WARN             |
      | 400        | true          | WARN             |
      | 404        | false         | WARN             |
      | 404        | true          | WARN             |
      | 499        | false         | WARN             |
      | 499        | true          | WARN             |
      | 500        | false         | ERROR            |
      | 500        | true          | ERROR            |
      | 503        | false         | ERROR            |
      | 503        | true          | ERROR            |
      | 599        | false         | ERROR            |
      | 599        | true          | ERROR            |
      | 600        | false         | INFO             |
      | 600        | true          | WARN             |
      | 999        | false         | INFO             |
      | 999        | true          | WARN             |

  Scenario: Logger detection cache key calculation
    Given an HTTP status code of 200
    And the request is slow: false
    When the logger detector determines the appropriate logger
    Then the cache key should be calculated correctly
    And the cache should store the result
