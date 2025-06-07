from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_endswith_modifier():
    sigma_rule = """
    title: Endswith modifier match
    logsource:
      product: test
    detection:
      selection1:
        field|endswith: end
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'value-at-end' }
    assert matcher.match(event) is True


def test_no_match_with_endswith_modifier_when_suffix_missing():
    sigma_rule = """
    title: Endswith modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|endswith: end
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'end-in-middle' }
    assert matcher.match(event) is False


def test_match_with_endswith_modifier_case_insensitive():
    sigma_rule = """
    title: Endswith modifier case-insensitive
    logsource:
      product: test
    detection:
      selection1:
        field|endswith: Suffix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'ends-with-suffix' }
    assert matcher.match(event) is True


def test_match_with_cased_endswith_modifier_exact_case():
    sigma_rule = """
    title: Cased endswith modifier exact match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|endswith: Suffix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'endsWithSuffix' }
    assert matcher.match(event) is True


def test_no_match_with_cased_endswith_modifier_wrong_case():
    sigma_rule = """
    title: Cased endswith modifier no match
    logsource:
      product: test
    detection:
      selection1:
        field|cased|endswith: Suffix
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'endswithsuffix' }
    assert matcher.match(event) is False


def test_match_with_multiple_values_in_endswith_list():
    sigma_rule = """
    title: Endswith list match
    logsource:
      product: test
    detection:
      selection1:
        field|endswith:
          - .exe
          - .dll
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'program.dll' }
    assert matcher.match(event) is True


def test_no_match_with_endswith_list_when_none_match():
    sigma_rule = """
    title: Endswith list no match
    logsource:
      product: test
    detection:
      selection1:
        field|endswith:
          - .log
          - .txt
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'report.json' }
    assert matcher.match(event) is False
