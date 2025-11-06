@security #@disabled
Feature: JWT Generator Service
  The service is responsible for generating JWT tokens mainly for internal service-to-service authentication

  Background:
    Given a PEM encoded random key pair
    And JWT generator service is initialized with valid configuration

  Scenario Outline: Generating an access token with valid credentials
    When an access token is requested with valid basic auth header "<basicAuthHeader>" and grant type "client_credentials"
    Then no exception should be thrown
    And the generated token should be valid
    And the token should contain the "test-authority" authority
    And the token should have the correct client ID
    And the token should have a valid expiration time
    Examples:
      | basicAuthHeader                    |
      | Basic aW50ZXJuYWw6dGVzdC1zZWNyZXQ= |

  Scenario Outline: Generating an access token with invalid credentials
    When an access token is requested with invalid basic auth header "<basicAuthHeader>" and grant type "client_credentials"
    Then an exception should be thrown
    And UnauthorizedException should be thrown
    Examples:
      | basicAuthHeader                                |
      | Basic aW52YWxpZC1jbGllbnQ6aW52YWxpZC1zZWNyZXQ= |
      | Basic                                          |
      | InvalidHeader                                  |

  Scenario Outline: Generating an access token with invalid grant type
    When an access token is requested with valid basic auth header "Basic cHJpdmF0ZTp0ZXN0LXNlY3JldA==" and grant type "<grantType>"
    Then an exception should be thrown
    And UnauthorizedException should be thrown
    Examples:
      | grantType          |
      | password           |
      | authorization_code |
      |                    |
