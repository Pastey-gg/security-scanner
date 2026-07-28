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


__all__ = ("GuardClassifier", "RuleType", "ScanService", "ScanSeverity", "ScanStatus")


# fmt: off
class ScanStatus(enum.StrEnum):
    clear  = enum.auto()
    fail   = enum.auto()
    review = enum.auto()


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


class RuleType(enum.StrEnum):
    simple = enum.auto()
    regex  = enum.auto()
    yara   = enum.auto()


class GuardClassifier(enum.StrEnum):
    S1  = "Violent Crimes"
    S2  = "Non-Violent Crimes"
    S3  = "Sex-Related Crimes"
    S4  = "Child Sexual Exploitation"
    S5  = "Defamation"
    S6  = "Specialized Advice"
    S7  = "Privacy"
    S8  = "Intellectual Property"
    S9  = "Indiscriminate Weapons"
    S10 = "Hate"
    S11 = "Suicide & Self-Harm"
    S12 = "Sexual Content"
    S13 = "Elections"
