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

import enum


__all__ = ("ScanService", "ScanSeverity", "ScanStatus")


# fmt: off
class ScanStatus(enum.Enum):
    passed = enum.auto()
    failed = enum.auto()
    manual = enum.auto()


class ScanService(enum.StrEnum):
    RULES  = enum.auto()
    YARA   = enum.auto()
    LLAMA  = enum.auto()
    TOKENS = enum.auto()


class ScanSeverity(enum.IntEnum):
    none     = 0
    low      = 1
    moderate = 2
    high     = 3
    critical = 4
