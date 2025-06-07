from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_cased_modifier_exact_case():
    sigma_rule = """
    title: Cased match exact
    logsource:
      product: test
    detection:
      selection1:
        field|cased: Value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'Value' }
    assert matcher.match(event) is True


def test_no_match_with_cased_modifier_different_case():
    sigma_rule = """
    title: Cased mismatch due to case
    logsource:
      product: test
    detection:
      selection1:
        field|cased: Value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'value' }  # lowercase
    assert matcher.match(event) is False


def test_no_match_with_cased_modifier_all_caps():
    sigma_rule = """
    title: Cased mismatch all caps
    logsource:
      product: test
    detection:
      selection1:
        field|cased: Value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'VALUE' }
    assert matcher.match(event) is False


def test_match_without_cased_modifier_case_insensitive():
    sigma_rule = """
    title: No cased modifier
    logsource:
      product: test
    detection:
      selection1:
        field: Value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'value' }
    assert matcher.match(event) is True
