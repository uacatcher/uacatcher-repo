from . import config
import os


class CodeQLTemplate:
    def __init__(self, raw_content:str):
        content = raw_content.split('===')
        self.query_base = content[0]
        self.predicate_group = content[1]
        self.predicate_item = content[2]
        self.predicates = []
        self.next_tag = 0

    def begin_group(self):
        self.current_items = []

    def add_item(self, *params):
        self.current_items.append(self.predicate_item % (*params,))

    def add_item_base(self, *params):
        self.query_base = self.query_base % (*params,)

    def end_group(self, *params):
        if len(self.current_items) == 0:
            group = "1=0"
        else:
            group = "or".join(["(" + p + ")" for p in self.current_items])
        self.predicates.append(
            self.predicate_group % (self.next_tag, *params, "(" + group + ")")
        )
        self.next_tag += 1

    def get_query(self):
        pred_part = "or".join(["(" + p + ")" for p in self.predicates])
        query = self.query_base % pred_part
        return query
