import time

from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_when_field_matches_selection():
    sigma_rule = """
    title: Single selection
    logsource:
      product: test
    detection:
      selection1:
        field:
          - value1
          - valuE2
          - value3
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'Value2' }   # Case insensitive by default
    assert matcher.match(event) is True

def test_match_when_numeric_field_matches_selection():
    sigma_rule = """
    title: Single selection
    logsource:
      product: test
    detection:
      selection1:
        field:
          - 4
          - 8
          - 12.5
          - test
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 8.0 }
    assert matcher.match(event) is True


def test_no_match_when_field_does_not_match_selection():
    sigma_rule = """
    title: Single selection
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'other' }
    assert matcher.match(event) is False


def test_match_with_and_condition():
    sigma_rule = """
    title: AND condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: sel1 and sel2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1', 'field2': 'value2' }
    assert matcher.match(event) is True


def test_no_match_with_and_condition():
    sigma_rule = """
    title: AND condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: sel1 and sel2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1' }
    assert matcher.match(event) is False


def test_match_with_or_condition():
    sigma_rule = """
    title: OR condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: sel1 or sel2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field2': 'value2' }
    assert matcher.match(event) is True


def test_match_with_not_condition():
    sigma_rule = """
    title: NOT condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      condition: not sel1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'other' }
    assert matcher.match(event) is True


def test_no_match_with_not_condition():
    sigma_rule = """
    title: NOT condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      condition: not sel1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1' }
    assert matcher.match(event) is False


def test_match_with_and_not_condition():
    sigma_rule = """
    title: NOT condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
        field2:
          - value2a
          - value2b
          - value2c
          - value2d
          - value2e
          - value2f
          - value2g
          - value2h
          - value2i
          - value2j
          - value2k
          - value2l
          - value2m
          - value2n
          - value2o
          - value2p
          - value2q
          - value2r
          - value2s
          - value2t
          - value2u
          - value2v
          - value2w
          - value2x
          - value2y
          - value2z
      sel2:
        field3: value3 
      condition: sel1 and not sel2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1', 'field2': 'value2V', 'field3': 'other' }
    assert matcher.match(event) is True

def test_match_with_double_not_condition():
    sigma_rule = """
    title: NOT condition
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2 
      condition: not sel1 and not sel2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'valueX', 'field2': 'valueY' }
    assert matcher.match(event) is True

def test_match_with_all_of_wildcard():
    sigma_rule = """
    title: All of wildcard
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: all of sel*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1', 'field2': 'value2' }
    assert matcher.match(event) is True


def test_no_match_with_all_of_wildcard():
    sigma_rule = """
    title: All of wildcard
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: all of sel*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field1': 'value1' }
    assert matcher.match(event) is False


def test_match_with_1_of_wildcard():
    sigma_rule = """
    title: One of wildcard
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: 1 of sel*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field2': 'value2' }
    assert matcher.match(event) is True


def test_no_match_with_1_of_wildcard():
    sigma_rule = """
    title: One of wildcard
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      condition: 1 of sel*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field3': 'value3' }
    assert matcher.match(event) is False


def test_match_with_combined_conditions():
    sigma_rule = """
    title: Combined logic
    logsource:
      product: test
    detection:
      sel1:
        field1: value1
      sel2:
        field2: value2
      sel3:
        field3: value3
      condition: (sel1 or sel2) and sel3
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'field2': 'value2',
        'field3': 'value3'
    }
    assert matcher.match(event) is True
