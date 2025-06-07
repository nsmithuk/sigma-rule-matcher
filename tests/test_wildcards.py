from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_asterisk_wildcard_suffix():
    sigma_rule = """
    title: Asterisk wildcard suffix
    logsource:
      product: test
    detection:
      selection1:
        field: val*
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'value123'}
    assert matcher.match(event) is True


def test_match_with_asterisk_wildcard_prefix():
    sigma_rule = """
    title: Asterisk wildcard prefix
    logsource:
      product: test
    detection:
      selection1:
        field: "*test"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'pretest'}
    assert matcher.match(event) is True


def test_match_with_asterisk_wildcard_middle():
    sigma_rule = """
    title: Asterisk wildcard middle
    logsource:
      product: test
    detection:
      selection1:
        field: admin*user
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'admin-root-user'}
    assert matcher.match(event) is True


def test_no_match_with_asterisk_wildcard():
    sigma_rule = """
    title: Asterisk wildcard no match
    logsource:
      product: test
    detection:
      selection1:
        field: val*
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'nope'}
    assert matcher.match(event) is False


def test_match_with_question_mark_wildcard():
    sigma_rule = """
    title: Question mark wildcard
    logsource:
      product: test
    detection:
      selection1:
        field: te?t
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'test'}
    assert matcher.match(event) is True


def test_no_match_with_question_mark_wildcard():
    sigma_rule = """
    title: Question mark wildcard no match
    logsource:
      product: test
    detection:
      selection1:
        field: te?t
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'te--t'}
    assert matcher.match(event) is False


def test_match_with_combined_wildcards():
    sigma_rule = """
    title: Combined wildcard pattern
    logsource:
      product: test
    detection:
      selection1:
        field: "*foo?bar*"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'field': 'abc-foo1bar-xyz'}
    assert matcher.match(event) is True
