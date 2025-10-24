#@disabled
Feature: Log Context Filter

  Scenario: Storing basic request parameters in MDC
    Given an HTTP request with URI "/api/users" and method "GET"
    And a remote IP "192.168.1.100"
    And an application name "test-app"
    When the LogContextFilter processes the request
    Then the MDC should contain REQUEST_PATH with value "/api/users"
    And the MDC should contain REQUEST_METHOD with value "GET"
    And the MDC should contain REMOTE_IP with value "192.168.1.100"
    And the MDC should contain APP_NAME with value "test-app"
    And the MDC should not contain USERNAME

  Scenario: Storing user information from Principal
    Given an HTTP request with URI "/api/users" and method "GET"
    And a Principal with name "testuser"
    When the LogContextFilter processes the request
    Then the MDC should contain USERNAME with value "testuser"

  Scenario: Storing user information from Authentication
    Given an HTTP request with URI "/api/users" and method "GET"
    And an Authentication with name "testuser" and principal object
    When the LogContextFilter processes the request
    Then the MDC should contain USERNAME with value "testuser"

  Scenario: Storing user ID from AbstractAuthenticationToken with JWT details
    Given an HTTP request with URI "/api/users" and method "GET"
    And an AbstractAuthenticationToken with subject "user123"
    When the LogContextFilter processes the request
    Then the MDC should contain USERNAME with value "token-user"

  Scenario: Handling missing application context
    Given an HTTP request with URI "/api/users" and method "GET"
    When the LogContextFilter processes the request
    Then the MDC should contain REQUEST_PATH with value "/api/users"
    And the MDC should contain REQUEST_METHOD with value "GET"
    And the MDC should not contain APP_NAME

  Scenario: Handling blank application name
    Given an HTTP request with URI "/api/users" and method "GET"
    And an application name ""
    When the LogContextFilter processes the request
    Then the MDC should contain REQUEST_PATH with value "/api/users"
    And the MDC should contain REQUEST_METHOD with value "GET"
    And the MDC should not contain APP_NAME

  Scenario: Filter chain execution
    Given an HTTP request with URI "/api/users" and method "GET"
    When the LogContextFilter's doFilterInternal method is called
    Then the filter chain's doFilter method should be called
    And the MDC should contain REQUEST_PATH with value "/api/users"
    And the MDC should contain REQUEST_METHOD with value "GET"

  Scenario Outline: Storing different request parameters
    Given an HTTP request with URI "<uri>" and method "<method>"
    And a remote IP "<remoteIp>"
    When the LogContextFilter processes the request
    Then the MDC should contain REQUEST_PATH with value "<uri>"
    And the MDC should contain REQUEST_METHOD with value "<method>"
    And the MDC should contain REMOTE_IP with value "<remoteIp>"
    Examples:
      | uri           | method | remoteIp      |
      | /api/users    | GET    | 192.168.1.100 |
      | /api/products | POST   | 10.0.0.1      |
      | /api/orders   | PUT    | 172.16.0.1    |
      | /api/auth     | DELETE | 127.0.0.1     |
