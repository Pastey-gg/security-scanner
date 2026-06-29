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

from typing import TYPE_CHECKING, Any

from types_.pastes import FileRecord

from ...core.config import CONFIG
from . import BaseScanner


if TYPE_CHECKING:
    from types_.pastes import FileRecord


__all__ = ("GeneralHacks",)


class GeneralHacks(BaseScanner):
    def __init__(self, file: FileRecord, /, *args: Any, **kwargs: Any) -> None:
        super().__init__(file, *args, **kwargs)
        self._score: int = 0

    def scan(self) -> None:
        kws: list[str] = CONFIG["malicious_scanners"]["rules"]

        for kw in kws:
            kw = kw.lower()

            if kw not in (str(self.file.name).lower(), self.file.content.lower()):
                continue

            self._score = 100

    def passes(self) -> bool:
        return self._score < 100

    @property
    def score(self) -> int:
        return self._score
