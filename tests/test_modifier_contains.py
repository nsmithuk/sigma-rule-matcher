from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_contains_modifier():
    sigma_rule = """
    title: Contains modifier match
    logsource:
      product: test
    detection:
      selection1:
        field|contains: part
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'some-partial-value' }
    assert matcher.match(event) is True


def test_no_match_with_contains_modifier_when_absent():
    sigma_rule = """
    title: Contains modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|contains: part
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'completelydifferent' }
    assert matcher.match(event) is False


def test_match_with_contains_modifier_case_insensitive():
    sigma_rule = """
    title: Contains modifier case-insensitive
    logsource:
      product: test
    detection:
      selection1:
        field|contains: Partial
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'some-partial-value' }
    assert matcher.match(event) is True


def test_match_with_cased_contains_modifier_exact_case():
    sigma_rule = """
    title: Contains with cased modifier exact match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|contains: Part
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'PrePartPost' }
    assert matcher.match(event) is True


def test_no_match_with_cased_contains_modifier_wrong_case():
    sigma_rule = """
    title: Contains with cased modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|contains: Part
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'prepartpost' }
    assert matcher.match(event) is False


def test_match_with_multiple_values_in_contains_list():
    sigma_rule = """
    title: Contains with list
    logsource:
      product: test
    detection:
      selection1:
        field|contains:
          - foo
          - bar
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'something-with-bar-inside' }
    assert matcher.match(event) is True


def test_no_match_with_contains_list_when_none_match():
    sigma_rule = """
    title: Contains with list no match
    logsource:
      product: test
    detection:
      selection1:
        field|contains:
          - alpha
          - beta
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'gamma-delta' }
    assert matcher.match(event) is False

def test_match_with_contains_and_startswith_modifiers_on_same_field():
    sigma_rule = """
    title: Contains modifier match
    logsource:
      product: test
    detection:
      selection1:
        field|contains: part
        field|startswith: some
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'some-partial-value' }
    assert matcher.match(event) is True
