from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_re_modifier():
    sigma_rule = """
    title: Regex match basic
    logsource:
      product: test
    detection:
      selection1:
        field|re: "^abc[0-9]+$"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'abc123' }
    assert matcher.match(event) is True


def test_no_match_with_re_modifier_invalid_input():
    sigma_rule = """
    title: Regex mismatch basic
    logsource:
      product: test
    detection:
      selection1:
        field|re: "^abc[0-9]+$"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'xyz123' }
    assert matcher.match(event) is False


def test_match_with_re_i_modifier_case_insensitive():
    sigma_rule = """
    title: Regex match case-insensitive
    logsource:
      product: test
    detection:
      selection1:
        field|re|i: "^abc[0-9]+$"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'ABC456' }
    assert matcher.match(event) is True


def test_no_match_with_re_modifier_due_to_case_sensitivity():
    sigma_rule = """
    title: Regex mismatch without `i`
    logsource:
      product: test
    detection:
      selection1:
        field|re: "^abc[0-9]+$"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': 'ABC456' }
    assert matcher.match(event) is False


def test_match_with_re_m_modifier_multiline():
    sigma_rule = """
    title: Regex match multiline
    logsource:
      product: test
    detection:
      selection1:
        field|re|m: "^ERROR:"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': "info: ok\nERROR: something failed" }
    assert matcher.match(event) is True


def test_match_with_re_s_modifier_dot_matches_newline():
    sigma_rule = """
    title: Regex match single line (dot matches newline)
    logsource:
      product: test
    detection:
      selection1:
        field|re|s: "first.*last"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': "first line\nsecond line\nlast" }
    assert matcher.match(event) is True


def test_no_match_with_re_without_s_modifier_dot_does_not_match_newline():
    sigma_rule = """
    title: Regex no match without `s`
    logsource:
      product: test
    detection:
      selection1:
        field|re: "first.*last"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': "first line\nsecond line\nlast" }
    assert matcher.match(event) is False


def test_match_with_re_im_combined_modifiers():
    sigma_rule = """
    title: Regex match with `im` modifiers
    logsource:
      product: test
    detection:
      selection1:
        field|re|i|m: "^error:"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'field': "Info: All good\nERROR: Something went wrong" }
    assert matcher.match(event) is True
