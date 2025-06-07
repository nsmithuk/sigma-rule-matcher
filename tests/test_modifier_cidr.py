from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_cidr_modifier_ipv4():
    sigma_rule = """
    title: CIDR match ipv4
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr: 192.168.0.0/16
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': '192.168.42.5' }
    assert matcher.match(event) is True


def test_no_match_with_cidr_modifier_ipv4_out_of_range():
    sigma_rule = """
    title: CIDR no match out of range
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr: 192.168.0.0/16
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': '10.0.0.1' }
    assert matcher.match(event) is False


def test_match_with_cidr_modifier_ipv6():
    sigma_rule = """
    title: CIDR match ipv6
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr: 2001:db8::/32
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': '2001:db8::1' }
    assert matcher.match(event) is True


def test_match_with_multiple_cidr_ranges():
    sigma_rule = """
    title: CIDR match from list
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr:
          - 10.0.0.0/8
          - 172.16.0.0/12
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': '172.20.0.5' }
    assert matcher.match(event) is True


def test_no_match_with_multiple_cidr_ranges():
    sigma_rule = """
    title: CIDR list no match
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr:
          - 10.0.0.0/8
          - 172.16.0.0/12
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': '192.168.100.1' }
    assert matcher.match(event) is False


def test_no_match_with_cidr_modifier_invalid_ip():
    sigma_rule = """
    title: CIDR match invalid IP
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr: 192.168.0.0/16
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = { 'src_ip': 'not-an-ip' }
    assert matcher.match(event) is False


def test_no_match_with_cidr_modifier_missing_field():
    sigma_rule = """
    title: CIDR match missing field
    logsource:
      product: test
    detection:
      selection1:
        src_ip|cidr: 192.168.0.0/16
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {}
    assert matcher.match(event) is False
