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

from typing import TYPE_CHECKING, Any, TypedDict

import asyncpg


if TYPE_CHECKING:
    import datetime


class FileT(TypedDict):
    id: str
    paste_id: str
    name: str | None
    language: str | None
    content: str
    deleted_at: datetime.datetime | None
    character_count: int
    line_count: int


class PasteT(TypedDict):
    id: str
    created_at: datetime.datetime
    web: bool
    views: int
    expires_at: datetime.datetime | None
    deleted_at: datetime.datetime | None
    remaining_views: int | None
    hashed_password: str | None
    safety_token: str


class PasteRecordT(TypedDict):
    record: PasteT


class FileRecord(asyncpg.Record):
    id: str
    paste_id: str
    name: str | None
    language: str | None
    content: str
    deleted_at: datetime.datetime | None
    character_count: int
    line_count: int

    def __getattr__(self, name: str) -> Any:
        return self[name]


class PasteRecord(asyncpg.Record):
    id: str
    created_at: datetime.datetime
    web: bool
    views: int
    expires_at: datetime.datetime | None
    deleted_at: datetime.datetime | None
    remaining_views: int | None
    hashed_password: str | None
    safety_token: str

    def __getattr__(self, name: str) -> Any:
        return self[name]
