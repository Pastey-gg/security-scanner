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

import base64
import binascii
import re
from typing import TYPE_CHECKING, Any

from . import BaseScanner


if TYPE_CHECKING:
    from collections.abc import Callable

    from types_.pastes import FileRecord


class TokenScanner(BaseScanner):
    DISCORD_REGEX: re.Pattern[str] = re.compile(r"[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}")
    PYPI_REGEX: re.Pattern[str] = re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}")
    GITHUB_REGEX: re.Pattern[str] = re.compile(r"((ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36})")

    def __init__(self, file: FileRecord, /, *args: Any, **kwargs: Any) -> None:
        super().__init__(file, *args, **kwargs)
        self.rules: dict[str, Callable[..., bool]] = {"discord": self.discord}
        self._extras: dict[str, str] = {}

    def validate_discord_token(self, token: str) -> bool:
        try:
            (user_id, _, _) = token.split(".")
            user_id = int(base64.b64decode(user_id + "=" * (len(user_id) % 4), validate=True))
        except ValueError, binascii.Error:
            return False
        else:
            return True

    def discord(self) -> bool: ...

    def github(self) -> bool: ...

    def pypi(self) -> bool: ...

    def scan(self) -> None:
        for func in self.rules.values():
            if func():
                # LOGGER...
                ...
