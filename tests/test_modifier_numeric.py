from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher

# --- GT (greater than) ---

def test_match_with_gt_modifier():
    sigma_rule = """
    title: Greater than match
    logsource:
      product: test
    detection:
      selection1:
        value|gt:
          - 10
          - 20
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 15 }
    assert matcher.match(event) is True


def test_no_match_with_gt_modifier():
    sigma_rule = """
    title: Greater than no match
    logsource:
      product: test
    detection:
      selection1:
        value|gt: 10
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 10 }
    assert matcher.match(event) is False


# --- GTE (greater than or equal) ---

def test_match_with_gte_modifier_equal():
    sigma_rule = """
    title: Greater than or equal match (equal)
    logsource:
      product: test
    detection:
      selection1:
        value|gte: 10
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 10 }
    assert matcher.match(event) is True


def test_match_with_gte_modifier_greater():
    sigma_rule = """
    title: Greater than or equal match (greater)
    logsource:
      product: test
    detection:
      selection1:
        value|gte: 10
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 20 }
    assert matcher.match(event) is True


def test_no_match_with_gte_modifier():
    sigma_rule = """
    title: Greater than or equal no match
    logsource:
      product: test
    detection:
      selection1:
        value|gte: 10
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 5 }
    assert matcher.match(event) is False


# --- LT (less than) ---

def test_match_with_lt_modifier():
    sigma_rule = """
    title: Less than match
    logsource:
      product: test
    detection:
      selection1:
        value|lt: 100
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 42 }
    assert matcher.match(event) is True


def test_no_match_with_lt_modifier():
    sigma_rule = """
    title: Less than no match
    logsource:
      product: test
    detection:
      selection1:
        value|lt: 100
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 100 }
    assert matcher.match(event) is False


# --- LTE (less than or equal) ---

def test_match_with_lte_modifier_equal():
    sigma_rule = """
    title: Less than or equal match (equal)
    logsource:
      product: test
    detection:
      selection1:
        value|lte: 100
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 100 }
    assert matcher.match(event) is True


def test_match_with_lte_modifier_less():
    sigma_rule = """
    title: Less than or equal match (less)
    logsource:
      product: test
    detection:
      selection1:
        value|lte: 100
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 42 }
    assert matcher.match(event) is True


def test_no_match_with_lte_modifier():
    sigma_rule = """
    title: Less than or equal no match
    logsource:
      product: test
    detection:
      selection1:
        value|lte: 100
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'value': 101 }
    assert matcher.match(event) is False


# --- Optional edge case ---

def test_no_match_with_missing_field_for_comparison():
    sigma_rule = """
    title: Comparison with missing field
    logsource:
      product: test
    detection:
      selection1:
        value|gt: 5
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {}
    assert matcher.match(event) is False
