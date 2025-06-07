import fnmatch
import re
from collections.abc import Callable

from boolean import AND, NOT, OR, BooleanAlgebra, Symbol
from boolean import Expression as BooleanExpression

from sigma_rule_matcher.condition_evaluator import (
    AndNotConditionEvaluator,
    DynamicBooleanEvaluator,
    BooleanConditionEvaluator,
    FalseConditionEvaluator,
    TrueConditionEvaluator,
    AndConditionEvaluator,
    OrConditionEvaluator,
    OrNotConditionEvaluator
)

ConditionEvaluatorFunction = Callable[[], BooleanConditionEvaluator]

class Condition:
    def __init__(self, condition: str, selectors: set[str]):
        condition_lower = condition.lower()

        if "1 of them" == condition_lower:
            condition = "1 of *"
        elif "all of them" == condition_lower:
            condition = "all of *"

        elif "1 of them" in condition_lower:
            raise NotImplementedError("'1 of them' is only supported on its own, not with other conditions")
        elif "all of them" in condition_lower:
            raise NotImplementedError("'all of them' is only supported on its own, not with other conditions")

        # ---

        # Technically possible that a selector can end with 'of', but even if so it still won't match the regex.
        # This is more of a crude check before we have to spin up a regex.
        if "of " in condition_lower:
            # Match the '1|all of <pattern>' groupings.
            matches = re.findall(r'((?:1|all) of ([\w?*]+))', condition, flags=re.IGNORECASE)

            for full_match, pattern in matches:
                # Find all selectors that match the pattern.
                matched_selectors: set[str] = set()
                for selector_name in selectors:
                    if fnmatch.fnmatch(selector_name, pattern):
                        matched_selectors.add(selector_name)

                # Replace the original condition string with the expanded one.
                if len(matched_selectors) == 0:
                    raise ValueError(f"No selectors matched '{full_match}'")

                logic = " AND " if full_match.lower().startswith("all") else " OR "
                of_condition = "(" + logic.join(matched_selectors) + ")"
                condition = condition.replace(full_match, of_condition)

        self._condition: BooleanExpression = BooleanAlgebra().parse(condition, simplify=True)
        self._symbols: list[Symbol] = self._condition.get_symbols()

        # ---

        # Validate that all selectors that are referenced, exist.
        symbols = {str(s) for s in self._symbols}
        missing_selectors = symbols - selectors
        if len(missing_selectors) > 0:
            raise ValueError(f"Condition references selectors that are not present: {missing_selectors}")

        # ---

        evaluator = self._get_static_evaluator(self._condition)

        if evaluator is None:
            def get_instance() -> BooleanConditionEvaluator:
                return DynamicBooleanEvaluator(self._condition)
            evaluator = get_instance

        self.evaluator: ConditionEvaluatorFunction = evaluator


    @staticmethod
    def _get_static_evaluator(expr: BooleanExpression) -> ConditionEvaluatorFunction | None:
        len_symbols = len(expr.symbols)

        if len_symbols > 2:
            return None

        if len_symbols == 1:
            if isinstance(expr, NOT) and len(expr.args) == 1 and isinstance(expr.args[0], Symbol):
                def get_instance() -> BooleanConditionEvaluator:
                    return FalseConditionEvaluator(str(expr.args[0]))
            else:
                def get_instance() -> BooleanConditionEvaluator:
                    return TrueConditionEvaluator(str(expr))

            return get_instance

        if len_symbols == 2 and (isinstance(expr, AND) or isinstance(expr, OR)):
            left, right = expr.args

            if isinstance(left, Symbol) and isinstance(right, Symbol):
                if isinstance(expr, AND):
                    def get_instance() -> BooleanConditionEvaluator:
                        return AndConditionEvaluator(str(left), str(right))
                else:
                    def get_instance() -> BooleanConditionEvaluator:
                        return OrConditionEvaluator(str(left), str(right))

                return get_instance


            if not (isinstance(left, NOT) and isinstance(right, NOT)):
                if isinstance(right, NOT):
                    must_be_true, must_not_be_true = left, right.args[0]
                else:
                    must_be_true, must_not_be_true = right, left.args[0]

                if isinstance(expr, AND):
                    def get_instance() -> BooleanConditionEvaluator:
                        return AndNotConditionEvaluator(symbol_that_must_be_true=str(must_be_true), symbol_that_must_be_false=str(must_not_be_true))
                else:
                    def get_instance() -> BooleanConditionEvaluator:
                        return OrNotConditionEvaluator(symbol_that_must_be_true=str(must_be_true), symbol_that_must_be_false=str(must_not_be_true))

                return get_instance

        return None

    def get_expression(self) -> BooleanExpression:
        return self._condition

    def get_symbols(self) -> list[str]:
        return [str(s) for s in self._symbols]

    def get_instance(self) -> BooleanConditionEvaluator:
        return self.evaluator()
