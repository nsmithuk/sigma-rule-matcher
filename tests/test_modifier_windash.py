from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_windash_slash_prefix():
    sigma_rule = """
    title: windash matches slash prefix
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "/exec" }
    assert matcher.match(event) is True


def test_match_with_windash_en_dash():
    sigma_rule = """
    title: windash matches en dash
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "–exec" }  # en dash (U+2013) # noqa: RUF001
    assert matcher.match(event) is True


def test_match_with_windash_em_dash():
    sigma_rule = """
    title: windash matches em dash
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "—exec" }  # em dash (U+2014)
    assert matcher.match(event) is True


def test_match_with_windash_horizontal_bar():
    sigma_rule = """
    title: windash matches horizontal bar
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "―exec" }  # horizontal bar (U+2015)
    assert matcher.match(event) is True


def test_match_with_windash_multiple_arguments():
    sigma_rule = """
    title: windash matches one among many args
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash|contains: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "/a /b /exec /c" }
    assert matcher.match(event) is True


def test_no_match_with_windash_unrelated_command():
    sigma_rule = """
    title: windash no match
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'command_line': "/run" }
    assert matcher.match(event) is False


def test_no_match_with_windash_missing_field():
    sigma_rule = """
    title: windash no match on missing field
    logsource:
      product: test
    detection:
      selection1:
        command_line|windash: "-exec"
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {}
    assert matcher.match(event) is False
