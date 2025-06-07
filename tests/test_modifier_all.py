from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_contains_all_modifier_on_string():
    sigma_rule = """
    title: contains|all modifier match on scalar string
    logsource:
      product: test
    detection:
      selection1:
        CommandLine|contains|all:
          - ping
          - localhost
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)

    event = {'CommandLine': 'ping localhost -t'}
    assert matcher.match(event) is True


def test_no_match_with_contains_all_modifier_missing_one_substring():
    sigma_rule = """
    title: contains|all modifier with missing substring
    logsource:
      product: test
    detection:
      selection1:
        CommandLine|contains|all:
          - ping
          - localhost
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)

    event = {'CommandLine': 'ping 127.0.0.1'}
    assert matcher.match(event) is False


def test_match_with_contains_all_modifier_substrings_out_of_order():
    sigma_rule = """
    title: contains|all modifier with unordered substrings
    logsource:
      product: test
    detection:
      selection1:
        CommandLine|contains|all:
          - /ecp/default.aspx
          - __VIEWSTATEGENERATOR=
          - __VIEWSTATE=
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)

    event = {
        'CommandLine': 'GET /ecp/default.aspx?__VIEWSTATEGENERATOR=ABC&__VIEWSTATE=xyz'
    }
    assert matcher.match(event) is True


def test_no_match_with_contains_all_modifier_missing_all():
    sigma_rule = """
    title: contains|all modifier with no matches
    logsource:
      product: test
    detection:
      selection1:
        CommandLine|contains|all:
          - alpha
          - beta
          - gamma
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)

    event = {'CommandLine': 'echo hello world'}
    assert matcher.match(event) is False
