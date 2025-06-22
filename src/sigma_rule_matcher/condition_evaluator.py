from abc import ABC, abstractmethod

from boolean import Expression as BooleanExpression
from boolean import Symbol

# We return None if we don't have enough data to reach a conclusion. Otherwise we return a specific bool answer.
ConditionCheckResult = None | bool

class BooleanConditionEvaluator(ABC):
    @abstractmethod
    def evaluate(self, symbol:str, *,  value: bool) -> ConditionCheckResult:
        """Evaluate the condition against the given event."""

# ----------------------------------------------------------------------------------------------

class DynamicBooleanEvaluator(BooleanConditionEvaluator):
    """
    Evaluate the condition against the given event.
    This is used when the condition is not a simple AND/OR.
    """
    def __init__(self, expr: BooleanExpression):
        self.expr: BooleanExpression = expr

    def evaluate(self, symbol:str, *,  value: bool) -> ConditionCheckResult:

        fields = {Symbol(symbol): self.expr.TRUE if value else self.expr.FALSE}

        # We track the condition state per selector, for lazy validation.
        self.expr = self.expr.subs(fields, simplify=True)

        if self.expr == self.expr.TRUE:
            return True

        if self.expr == self.expr.FALSE:
            return False

        return None # We don't know yet.

# ----------------------------------------------------------------------------------------------

class TrueConditionEvaluator(BooleanConditionEvaluator):
    def __init__(self, symbol: str):
        self.symbol = symbol

    def evaluate(self, symbol:str, *, value: bool) -> ConditionCheckResult:
        if symbol != self.symbol:
            raise Exception(f"Invalid symbol {symbol}")
        return value

class FalseConditionEvaluator(TrueConditionEvaluator):
    def evaluate(self, symbol:str, *, value: bool) -> ConditionCheckResult:
        return not super().evaluate(symbol, value=value)

# ----------------------------------------------------------------------------------------------

class DuelSymbolConditionEvaluator(BooleanConditionEvaluator):
    def __init__(self, symbol_a: str, symbol_b: str):
        self.symbol_a = symbol_a
        self.symbol_b = symbol_b
        self.valid_symbol = {symbol_a, symbol_b}
        self.seen_symbols: dict[str, bool] = {}

    @abstractmethod
    def evaluate(self, symbol: str, *, value: bool) -> ConditionCheckResult:
        if symbol not in self.valid_symbol:
            raise Exception(f"Invalid symbol {symbol}")

        if symbol in self.seen_symbols:
            raise Exception(f"Duplicate symbol {symbol}")

        self.seen_symbols[symbol] = value

# ----------------------------------------------------------------------------------------------

class OrConditionEvaluator(DuelSymbolConditionEvaluator):
    def evaluate(self, symbol: str, *, value: bool) -> ConditionCheckResult:
        super().evaluate(symbol, value=value)

        if value:
            return True

        if len(self.seen_symbols) < 2:
            return None # We don't know yet.

        return self.seen_symbols[self.symbol_a] or self.seen_symbols[self.symbol_b]

class OrNotConditionEvaluator(OrConditionEvaluator):
    def __init__(self, symbol_that_must_be_true: str, symbol_that_must_be_false: str):
        super().__init__(symbol_that_must_be_true, symbol_that_must_be_false)

    def evaluate(self, symbol: str, *, value: bool) -> ConditionCheckResult:
        # We expect symbol_b to be false. We therefore expect the inverse action of parent `OrConditionEvaluator`.
        if symbol == self.symbol_b:
            value = not value

        return super().evaluate(symbol, value=value)

# ----------------------------------------------------------------------------------------------

class AndConditionEvaluator(DuelSymbolConditionEvaluator):
    def evaluate(self, symbol: str, *, value: bool) -> ConditionCheckResult:
        super().evaluate(symbol, value=value)

        if not value:
            return False

        if len(self.seen_symbols) < 2:
            return None # We don't know yet.

        return self.seen_symbols[self.symbol_a] and self.seen_symbols[self.symbol_b]

class AndNotConditionEvaluator(AndConditionEvaluator):
    def __init__(self, symbol_that_must_be_true: str, symbol_that_must_be_false: str):
        super().__init__(symbol_that_must_be_true, symbol_that_must_be_false)

    def evaluate(self, symbol: str, *, value: bool) -> ConditionCheckResult:
        # We expect symbol_b to be false. We therefore expect the inverse action of parent `AndConditionEvaluator`.
        if symbol == self.symbol_b:
            value = not value

        return super().evaluate(symbol, value=value)
