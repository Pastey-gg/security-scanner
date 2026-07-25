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

from __future__ import annotations

from typing import TYPE_CHECKING, NotRequired, TypedDict


if TYPE_CHECKING:
    import datetime

    from core.enums import *


class LineDetailsT(TypedDict):
    start_line: int
    start_char: int
    end_line: int
    end_char: int


class ScanResultT(TypedDict):
    status: ScanStatus
    service: ScanService
    severity: ScanSeverity
    reason: NotRequired[str]
    lines: NotRequired[LineDetailsT]
    timestamp: datetime.datetime
    paste_id: str
