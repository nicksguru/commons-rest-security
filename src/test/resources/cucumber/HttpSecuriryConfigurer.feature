@security #@disabled
Feature: HTTP security configuration
  As a developer
  I want to configure HTTP security for my application
  So that I can protect my endpoints with appropriate authentication and authorization

  Background:
    Given HttpSecurityConfigurer is initialized with default settings

  Scenario: Protect endpoints with any authentication
    When the following endpoints are protected with any authentication:
      | /api/public/** |
      | /v1/users/**   |
    Then 'authenticated' should be called

  Scenario: Protect endpoints with specific roles
    When the following endpoints are protected with roles:
      | endpoint        | roles        |
      | /api/admin/**   | ROLE_ADMIN   |
      | /api/user/**    | ROLE_USER    |
      | /api/manager/** | ROLE_MANAGER |
    Then 'hasAnyAuthority' should be called

  Scenario: Configure HTTP method specific protection
    When the following endpoints are protected with roles:
      | endpoint           | roles      |
      | GET /api/read/**   | ROLE_USER  |
      | POST /api/write/** | ROLE_ADMIN |
    Then 'hasAnyAuthority' should be called

  Scenario: Configure role-based URL protection with correct order
    When the following role-to-URL mappings are configured:
      | role       | urls                  |
      | ROLE_USER  | /api/**, /public/**   |
      | ROLE_ADMIN | /admin/**, /manage/** |
    Then ROLE_ADMIN should be applied first and ROLE_USER second despite of the above order

  Scenario: Attempt to add allow rules after deny-all rule
    Given default access denied is set to true
    When attempting to protect endpoints after deny-all
    Then IllegalStateException should be thrown

  Scenario: Configure SSL requirement
    When a security configurer is initialized with SSL required
    Then all requests should require secure channel

  Scenario: Apply multiple customizers
    When multiple customizers are applied
    Then all customizers should be executed in order

  Scenario: Validate MVC pattern
    When invalid MVC pattern is used
    Then SecurityException should be thrown with message about MVC patterns

  Scenario: ROLE_ADMIN must be first after implicit sorting
    When attempting to configure ROLE_ADMIN and others in any order
    Then no exception should be thrown

  Scenario: Create raw path matcher
    When raw path matcher is created for "/api/**"
    Then raw path matcher should match paths starting with "/api/"
    And raw path matcher should not match other paths
