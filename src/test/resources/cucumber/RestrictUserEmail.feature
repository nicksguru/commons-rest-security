#@disabled
Feature: Restrict User Email

  Scenario Outline: User email is checked against an allow-list
    Given the following email allow-list:
      | pattern    |
      | <patterns> |
    And the user has the email "<userEmail>"
    When the user email is checked
    Then the exception should be of type "<exceptionType>"
    Examples:
      | patterns          | userEmail            | exceptionType            | comments                         |
      | ^.*@example\.com$ | test@example.com     |                          |                                  |
      | ^.*@example\.com$ | test@another.com     | EmailNotAllowedException |                                  |
      | ^.*@example\.com$ |                      | EmailNotAllowedException | no user email                    |
      |                   | test@another.com     | EmailNotAllowedException | no patterns - nothing is allowed |
      |                   |                      | EmailNotAllowedException | no patterns - nothing is allowed |
      | example\.com      | test@example.com     |                          |                                  |
      | example\.com      | example.com@test.com |                          |                                  |
      | ^test@, ^another@ | test@domain.com      |                          |                                  |
      | ^test@, ^another@ | another@domain.com   |                          |                                  |
      | ^test@, ^another@ | other@domain.com     | EmailNotAllowedException |                                  |
      | , ^test@,         | test@domain.com      |                          |                                  |
