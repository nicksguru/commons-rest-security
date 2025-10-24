@security #@disabled
Feature: Custom CORS Filter
  CustomCorsFilter should handle cross-origin requests appropriately based on the CORS feature flag and configuration

  Scenario Outline: CORS filter with feature flag enabled
    Given a CustomCorsFilter is created with allowed origins "<Allowed Origins>"
    When a request is made with origin "<Request Origin>"
    Then the response should have the "Access-Control-Allow-Origin" header with value "<Header Value>": <Response Has Header?>
    And the filter chain should be called: <Filter Chain Called?>
    Examples:
      | Allowed Origins                       | Request Origin      | Response Has Header? | Header Value        | Filter Chain Called? |
      | *                                     | https://example.com | true                 | https://example.com | true                 |
      | https://example.com                   | https://example.com | true                 | https://example.com | true                 |
      | https://example.com                   | http://localhost    | false                |                     | true                 |
      | https://example.com, http://localhost | http://localhost    | true                 | http://localhost    | true                 |
      | *                                     |                     | false                |                     | true                 |

  Scenario: CORS filter handles OPTIONS preflight request
    Given a CustomCorsFilter is created with allowed origins "*"
    And the request method is "OPTIONS"
    And the request has the following headers:
      | name   | value               |
      | Origin | https://example.com |
    When the filter is applied
    Then the response should have the "Access-Control-Allow-Origin" header with value "https://example.com"
    And the response should have the "Access-Control-Allow-Headers" header with value "Origin,Content-Type,Authorization"
    And the response should have the "Access-Control-Allow-Credentials" header
    And the response should have the "Access-Control-Allow-Methods" header with value "GET,POST,PUT,DELETE,OPTIONS"
    And the response should have the "Access-Control-Max-Age" header with value "0"
    And the response should have the "Vary" header with value "Origin"
    And the response should have the "Content-Length" header with value "0"
    And the response should have the "Content-Type" header with value "text/plain; charset=UTF-8"
    And the response status should be 200
    And the filter chain should not be called
