from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_startswith_modifier():
    sigma_rule = """
    title: Startswith modifier match
    logsource:
      product: test
    detection:
      selection1:
        field|startswith: start
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'start-of-value' }
    assert matcher.match(event) is True


def test_no_match_with_startswith_modifier_when_prefix_missing():
    sigma_rule = """
    title: Startswith modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|startswith: start
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'middle-start' }
    assert matcher.match(event) is False


def test_match_with_startswith_modifier_case_insensitive():
    sigma_rule = """
    title: Startswith modifier case-insensitive
    logsource:
      product: test
    detection:
      selection1:
        field|startswith: Prefix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'prefix-match' }
    assert matcher.match(event) is True


def test_match_with_cased_startswith_modifier_exact_case():
    sigma_rule = """
    title: Cased startswith modifier exact match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|startswith: Prefix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'Prefix123' }
    assert matcher.match(event) is True


def test_no_match_with_cased_startswith_modifier_wrong_case():
    sigma_rule = """
    title: Cased startswith modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|startswith: Prefix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'prefix123' }
    assert matcher.match(event) is False


def test_match_with_multiple_values_in_startswith_list():
    sigma_rule = """
    title: Startswith list match
    logsource:
      product: test
    detection:
      selection1:
        field|startswith:
          - foo
          - bar
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'bar-stuff' }
    assert matcher.match(event) is True


def test_no_match_with_startswith_list_when_none_match():
    sigma_rule = """
    title: Startswith list no match
    logsource:
      product: test
    detection:
      selection1:
        field|startswith:
          - alpha
          - beta
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'gamma-data' }
    assert matcher.match(event) is False
