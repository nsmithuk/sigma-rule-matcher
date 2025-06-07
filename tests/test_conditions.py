import pytest
from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher

from sigma_rule_matcher.condition_evaluator import (
    DynamicBooleanEvaluator,
    FalseConditionEvaluator,
    TrueConditionEvaluator,
    AndConditionEvaluator,
    OrConditionEvaluator,
    OrNotConditionEvaluator,
    AndNotConditionEvaluator,
)

def test_condition_single_selector_evaluates_correctly():
    sigma_rule = """
    title: Single condition
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1"
    assert isinstance(matcher.get_rule_condition().evaluator(), TrueConditionEvaluator)


def test_condition_and_operator_expands_to_and_expression():
    sigma_rule = """
    title: AND condition
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value2
      condition: selection1 and selection2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1&selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), AndConditionEvaluator)


def test_condition_or_operator_expands_to_or_expression():
    sigma_rule = """
    title: OR condition
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value2
      condition: selection1 or selection2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1|selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), OrConditionEvaluator)


def test_condition_not_operator_expands_to_negation():
    sigma_rule = """
    title: NOT condition
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: not selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~selection1"
    assert isinstance(matcher.get_rule_condition().evaluator(), FalseConditionEvaluator)


def test_condition_combined_and_or_with_parentheses():
    sigma_rule = """
    title: Complex logical condition
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value2
      selection3:
        field: value3
      condition: selection1 and (selection2 or selection3)
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1&(selection2|selection3)"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)


def test_condition_not_with_parentheses():
    sigma_rule = """
    title: NOT with parentheses
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value2
      condition: not (selection1 or selection2)
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~(selection1|selection2)"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)


def test_condition_one_of_wildcard_expands_to_or_expression():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: 1 of selection*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1|selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), OrConditionEvaluator)

def test_condition_one_of_wildcard_expands_the_single_expression():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: 1 of selection*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1"
    assert isinstance(matcher.get_rule_condition().evaluator(), TrueConditionEvaluator)

def test_condition_all_of_wildcard_expands_to_and_expression():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: all of selection*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1&selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), AndConditionEvaluator)

def test_condition_not_all_of_wildcard_expands_to_negated_and_expression():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: not all of selection*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~(selection1&selection2)"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)

def test_condition_one_of_and_not_clause_combines_correctly():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: 1 of selection* and not filter
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~filter&(selection1|selection2)"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)

def test_condition_combines_multiple_wildcard_groups():
    sigma_rule = """
    title: Unit Test 1
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter1:
        field: value
      filter2:
        field: value
      condition: 1 of selection* or all OF filter?
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "selection1|selection2|(filter1&filter2)"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)

def test_condition_for_one_of_them():
    sigma_rule = """
    title: Unsupported 1 of them
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: 1 of them
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "filter|selection1|selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)

def test_condition_for_all_of_them():
    sigma_rule = """
    title: Unsupported all of them
    logsource:
      product: test
    detection:
      selection1:
        field: value
      selection2:
        field: value
      filter:
        field: value
      condition: all of them
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "filter&selection1&selection2"
    assert isinstance(matcher.get_rule_condition().evaluator(), DynamicBooleanEvaluator)

def test_condition_for_and_not():
    sigma_rule = """
    title: Unsupported all of them
    logsource:
      product: test
    detection:
      selection1:
        field: value
      filter:
        field: value
      condition: selection1 and not filter
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~filter&selection1"
    assert isinstance(matcher.get_rule_condition().evaluator(), AndNotConditionEvaluator)

def test_condition_for_or_not():
    sigma_rule = """
    title: Unsupported all of them
    logsource:
      product: test
    detection:
      selection1:
        field: value
      filter:
        field: value
      condition: selection1 or not filter
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    assert str(matcher.get_rule_condition().get_expression()) == "~filter|selection1"
    assert isinstance(matcher.get_rule_condition().evaluator(), OrNotConditionEvaluator)

def test_condition_raises_for_unmatched_selector_pattern():
    sigma_rule = """
    title: No match for selector pattern
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: 1 of nonmatching*
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    with pytest.raises(ValueError, match="No selectors matched '1 of nonmatching\\*'"):
        RuleMatcher(rule)

def test_condition_raises_when_included_non_existing_symbol():
    sigma_rule = """
    title: No match for selector pattern
    logsource:
      product: test
    detection:
      selection1:
        field: value
      condition: selection1 and selection2
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    with pytest.raises(ValueError, match="Condition references selectors that are not present: {'selection2'}"):
        RuleMatcher(rule)
