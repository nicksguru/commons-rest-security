@security #@disabled
Feature: Composite Jwt Decoder
  Test various combinations of chained JWT decoders (each verifies own signature)

  Background:
    Given JWT token 'some dummy text'

  Scenario: Accept token after successful decoding (one decoder)
    Given 1 decoder in chain
    And decoder #1 accepts tokens
    When token is decoded
    Then access is granted
    And decoder #1 was called

  Scenario: Accept token after successful decoding (two decoders)
    Given 2 decoders in chain
    And decoder #1 accepts tokens
    And decoder #2 accepts tokens
    When token is decoded
    Then access is granted
    And decoder #1 was called
    But decoder #2 was not called

  Scenario: Deny token after failed decoding (one decoder)
    Given 1 decoder in chain
    And decoder #1 rejects tokens
    When token is decoded
    Then token is invalid
    And decoder #1 was called

  Scenario: Accept token if first decoder accepts & second one rejects
    Given 2 decoders in chain
    And decoder #1 accepts tokens
    And decoder #2 rejects tokens
    When token is decoded
    Then access is granted
    And decoder #1 was called
    But decoder #2 was not called

  Scenario: Accept token if first decoder rejects & second one accepts
    Given 2 decoders in chain
    And decoder #1 rejects tokens
    And decoder #2 accepts tokens
    When token is decoded
    Then access is granted
    And decoder #1 was called
    And decoder #2 was called

  Scenario: Accept token if both decoders accept
    Given 2 decoders in chain
    And decoder #1 accepts tokens
    And decoder #2 accepts tokens
    When token is decoded
    Then access is granted
    And decoder #1 was called
    But decoder #2 was not called

  Scenario: Deny token if both decoders reject
    Given 2 decoders in chain
    And decoder #1 rejects tokens
    And decoder #2 rejects tokens
    When token is decoded
    Then token is invalid
    And decoder #1 was called
    And decoder #2 was called

  Scenario: Deny token if there are no decoders
    Given no decoders
    When token is decoded
    Then token is invalid
