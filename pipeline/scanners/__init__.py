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

import abc
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from types_.pastes import FileRecord


class BaseScanner(abc.ABC):
    def __init__(self, file: FileRecord, /, *args: Any, **kwargs: Any) -> None:
        self.file = file
        self.paste_id = file.paste_id

    @abc.abstractmethod
    def scan(self) -> None: ...

    @abc.abstractmethod
    def passes(self) -> bool: ...

    @property
    @abc.abstractmethod
    def score(self) -> int: ...

    @abc.abstractmethod
    def extras(self) -> Any: ...
