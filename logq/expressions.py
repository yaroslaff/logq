from typing import Any, Literal, List
from types import CodeType
from evalidate import Expr, EvalException, base_eval_model
from collections.abc import Iterator
import sys


class Expression:
    expr: str
    code: CodeType
    param: Any
    def __init__(self, expr: str, param: Any = None):
        self.expr = expr
        self.param = param

        my_model = base_eval_model.clone()
        my_model.nodes.extend(['Call', 'Attribute'])
        my_model.attributes.extend(['startswith', 'endswith'])

        try:
            self.code = Expr(expr, model=my_model).code
        except EvalException as e:
            raise ValueError(f"Invalid expression({e}): {expr}") from e


class ExpressionCollection:

    onload: List[Expression]
    tag: List[Expression]
    rate: List[Expression]
    session: List[Expression]
    out: List[Expression]

    summarize: bool = False
    sort_field: str | None = None
    sort_reverse: bool = False

    def __init__(self):
        self.onload = list()
        self.tag = list()
        self.rate = list()
        self.session = list()
        self.out = list()



    def add(self, expr: str, where: Literal["onload", "tagging", "rate", "session", "out"], param: str | None):

        # add expression to appropriate place
        if where == "onload":
            self.onload.append(Expression(expr, param))
        elif where == "tagging":
            self.tag.append(Expression(expr, param))
        elif where == "rate":
            self.rate.append(Expression(expr, param))
        elif where == "session":
            self.session.append(Expression(expr, param))
        elif where == "out":
            self.out.append(Expression(expr, param))
        else:
            raise ValueError(f"Invalid expression location: {where}")

        
    def iter(self, where: Literal["onload", "tagging", "rate", "session", "out"]) -> Iterator[Expression]:
        if where == "onload":
            for e in self.onload:
                yield e
        elif where == "tagging":
            for e in self.tag:
                yield e
        elif where == "rate":
            for e in self.rate:
                yield e
        elif where == "session":
            for e in self.session:
                yield e
        elif where == "out":
            for e in self.out:
                yield e
        else:
            raise ValueError(f"Invalid expression location: {where}")

    def apply_all(self, where: Literal["onload", "tagging", "rate", "session", "out"], record: dict) -> bool:
        for e in self.iter(where):
            try:
                if not eval(e.code, None, record):
                    return False
            except NameError as ex:
                print(f"Name error in expression {e.expr!r}: {ex}. Fields: {' '.join(record.keys())}", file=sys.stderr)
                return False
        return True