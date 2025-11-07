#@disabled
Feature: Restrict Username

  Scenario Outline: Username is checked against a deny-list
    Given the following username deny-list:
      | username    |
      | <usernames> |
    And the user has the username "<username>"
    When the username is checked
    Then the exception should be of type "<exceptionType>"
    Examples:
      | usernames | username | exceptionType                | comments           |
      | test      | test     | UserAccountDisabledException |                    |
      | test      | TEST     | UserAccountDisabledException |                    |
      | test      | another  |                              |                    |
      |           | test     |                              | deny-list is empty |
      | test      |          | UserAccountDisabledException | missing username   |
