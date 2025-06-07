
from typing import Any

from sigma.conditions import ConditionAND
from sigma.modifiers import SigmaFieldReferenceModifier
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

from sigma_rule_matcher.condition import Condition
from sigma_rule_matcher.detection_evaluator import DetectionEvaluator
from sigma_rule_matcher.missing_field import MissingField
from sigma_rule_matcher.utils import get_by_dots


class RuleMatcher:

    _missing_field = MissingField()

    def __init__(self, rule: SigmaRule):
        self.rule = rule

        if len(self.rule.detection.condition) != 1:
            raise ValueError("Only a single condition value is expected")

        if len(self.rule.detection.detections.keys()) == 0:
            raise ValueError("No selectors found")

        self._condition: Condition = Condition(
            condition=self.rule.detection.condition[0],
            selectors=set(self.rule.detection.detections.keys()),
        )

        # ---

        self.detection_items: dict[int, DetectionEvaluator] = {}

        for symbol in self._condition.get_symbols():
            detection = self.rule.detection.detections[str(symbol)]
            for item in detection.detection_items:
                # We'll store it under the detection item's internal id, which will always be unique.
                self.detection_items[id(item)] = DetectionEvaluator(item)


    def get_rule_condition(self) -> Condition:
        return self._condition

    def match(self, event: dict[str, Any]) -> bool:
        expression = self.get_rule_condition().get_instance()

        # We only check selectors that are referenced in the condition.
        for symbol in self.get_rule_condition().get_symbols():
            detection = self.rule.detection.detections[symbol]

            selector_result = self._evaluate_detection_group(event, detection)

            result = expression.evaluate(symbol=symbol, value=selector_result)   # None | bool

            # result is None if we don't have an answer yet.
            if isinstance(result, bool):
                return result

        # If we've not simplified to TRUE by now, we're done.
        return False

    def _evaluate_detection_group(self, event: dict[str, Any], detection: SigmaDetection) -> bool:
        if detection.item_linking is not ConditionAND:
            raise NotImplementedError("Only AND is supported for item linking")

        for item in detection.detection_items:
            match = self._evaluate_selector_item(event, item)
            if not match:
                return False

        # We have an AND, so if nothing was false, we'll say all is true.

        return True

    def _evaluate_selector_item(self, event: dict[str, Any], detection_item: SigmaDetectionItem) -> bool:

        # We note that a value of None (null) could be explicitly set; so we have a special type for NotFound.
        event_value = get_by_dots(event, detection_item.field, self._missing_field)

        # ---

        if event_value and not isinstance(event_value, str | int | float | MissingField):
            raise NotImplementedError(f"Unknown input value type detected, type: '{type(event_value)}'.")

        # ---

        # This is a bit of a special case, so we'll keep it separate for now.
        if SigmaFieldReferenceModifier in detection_item.modifiers:

            if len(detection_item.value) != 1:
                raise NotImplementedError("only a single value allowed for field1")

            target_field_key = str(detection_item.value[0].field)
            target_field_value = get_by_dots(event, target_field_key, self._missing_field)

            return event_value == target_field_value

        # ---

        new_matcher = self.detection_items.get(id(detection_item))

        if not new_matcher:
            raise RuntimeError("No matcher found for field {symbol}/{detection_item.field}")

        return new_matcher.match(event_value)
