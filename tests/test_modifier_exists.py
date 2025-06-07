from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher

# --- exists: true ---

def test_match_with_exists_true_field_present():
    sigma_rule = """
    title: Exists true - field present
    logsource:
      product: test
    detection:
      selection1:
        field|exists: true
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'any value'}
    assert matcher.match(event) is True


def test_match_with_exists_true_field_present_but_empty():
    sigma_rule = """
    title: Exists true - field present but empty
    logsource:
      product: test
    detection:
      selection1:
        field|exists: true
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': ''}
    assert matcher.match(event) is True


def test_match_with_exists_true_field_present_none():
    sigma_rule = """
    title: Exists true - field is None
    logsource:
      product: test
    detection:
      selection1:
        field|exists: true
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': None}
    assert matcher.match(event) is True


def test_no_match_with_exists_true_field_missing():
    sigma_rule = """
    title: Exists true - field missing
    logsource:
      product: test
    detection:
      selection1:
        field|exists: true
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {}
    assert matcher.match(event) is False


# --- exists: false ---

def test_match_with_exists_false_field_missing():
    sigma_rule = """
    title: Exists false - field missing
    logsource:
      product: test
    detection:
      selection1:
        field|exists: false
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {}
    assert matcher.match(event) is True


def test_no_match_with_exists_false_field_present():
    sigma_rule = """
    title: Exists false - field present
    logsource:
      product: test
    detection:
      selection1:
        field|exists: false
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'something'}
    assert matcher.match(event) is False


def test_no_match_with_exists_false_field_present_empty():
    sigma_rule = """
    title: Exists false - field present and empty
    logsource:
      product: test
    detection:
      selection1:
        field|exists: false
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': ''}
    assert matcher.match(event) is False


def test_no_match_with_exists_false_field_present_none():
    sigma_rule = """
    title: Exists false - field is None
    logsource:
      product: test
    detection:
      selection1:
        field|exists: false
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': None}
    assert matcher.match(event) is False
