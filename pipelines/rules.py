"""Copyright 2026 Pastey-gg

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import dataclasses
import datetime
import logging
import re
from typing import TYPE_CHECKING

from core import CONFIG
from core.enums import *

from .base import BaseScanner, ScanResult


if TYPE_CHECKING:
    from types_.pastes import FilePaste
    from types_.scanners import RuleT


LOGGER: logging.Logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Rule:
    name: str
    type: RuleType
    action: ScanStatus
    rule: set[str] | re.Pattern[str]


class RulesScanner(BaseScanner):
    PRIORITY = 0
    SERVICE = ScanService.RULES

    def __init__(self) -> None:
        self.rules: list[Rule] = []

    def compile(self) -> None:
        rules: list[RuleT] = CONFIG["rules"]

        for r in rules:
            raw = r["rule"]
            type_ = RuleType(r["type"])
            action = ScanStatus(r["action"])

            if isinstance(raw, list) and type_ is RuleType.regex:
                raise ValueError("Rules with type 'regex' can only be singular strings.")

            compiled: re.Pattern[str] | set[str]

            if type_ is RuleType.regex:
                assert isinstance(raw, str)
                compiled = re.compile(raw)
            else:
                compiled = set(raw) if isinstance(raw, list) else {raw}

            rule = Rule(name=r["name"], type=type_, action=action, rule=compiled)
            self.rules.append(rule)

    def do_compund(self, name: str, content: str, *, rules: set[str]) -> bool:
        return any(all(t.lower() in content or t.lower() in name for t in rule) for rule in rules)

    def scan_file(self, file: FilePaste) -> ScanResult | None:
        name = file["name"] or "".lower()
        content = file["content"].lower()
        paste_id = file["paste_id"]

        if not content:
            return

        result = None
        for rule in self.rules:
            if rule.type is RuleType.simple:
                assert isinstance(rule.rule, set)

                result = self.do_compund(name, content, rules=rule.rule)
            elif rule.type is RuleType.regex:
                # TODO: ...
                ...

            if result:
                action = rule.action
                service = self.SERVICE
                severity = ScanSeverity.high if action is ScanStatus.fail else ScanSeverity.moderate
                reason = f"Failed on custom rule: '{rule.name}'."
                now = datetime.datetime.now(tz=datetime.UTC)

                return ScanResult(
                    status=action,
                    service=service,
                    severity=severity,
                    reason=reason,
                    paste_id=paste_id,
                    timestamp=now,
                    lines=None,
                )

    def scan(self, file: FilePaste) -> ScanResult | None:
        LOGGER.info("Running scan for (%s: %s) with %s scanner.", file["paste_id"], file["id"], self.SERVICE)
        result = self.scan_file(file)
        return result
