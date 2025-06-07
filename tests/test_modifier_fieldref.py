from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_fieldref_equal_values():
    sigma_rule = """
    title: Fieldref match equal values
    logsource:
      product: test
    detection:
      selection1:
        field1|fieldref: field2
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'field1': 'bob',
        'field2': 'bob'
    }
    assert matcher.match(event) is True


def test_no_match_with_fieldref_different_values():
    sigma_rule = """
    title: Fieldref no match
    logsource:
      product: test
    detection:
      selection1:
        field1|fieldref: field2
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'field1': 'bob',
        'field2': 'alice'
    }
    assert matcher.match(event) is False


def test_no_match_with_fieldref_missing_target_field():
    sigma_rule = """
    title: Fieldref target field missing
    logsource:
      product: test
    detection:
      selection1:
        field1|fieldref: field2
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'field1': 'bob'
        # 'field2' is missing
    }
    assert matcher.match(event) is False


def test_no_match_with_fieldref_missing_source_field():
    sigma_rule = """
    title: Fieldref source field missing
    logsource:
      product: test
    detection:
      selection1:
        field1|fieldref: field2
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'field2': 'bob'
        # 'field1' is missing
    }
    assert matcher.match(event) is False


def test_match_with_fieldref_nested_fields():
    sigma_rule = """
    title: Fieldref with nested fields
    logsource:
      product: test
    detection:
      selection1:
        user.name|fieldref: user.expected
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'user': {
            'name': 'bob',
            'expected': 'bob'
        }
    }
    assert matcher.match(event) is True


def test_no_match_with_fieldref_nested_fields():
    sigma_rule = """
    title: Fieldref with nested fields no match
    logsource:
      product: test
    detection:
      selection1:
        user.name|fieldref: user.expected
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {
        'user': {
            'name': 'bob',
            'expected': 'alice'
        }
    }
    assert matcher.match(event) is False
