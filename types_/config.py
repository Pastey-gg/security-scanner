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

from typing import TYPE_CHECKING, TypedDict


if TYPE_CHECKING:
    from .scanners import RuleT


class MQConfigT(TypedDict):
    host: str
    port: int
    user: str
    password: str
    queue_name: str


class DatabaseConfigT(TypedDict):
    dsn: str


class YARAConfigT(TypedDict):
    enable: bool
    rules_path: str


class LlamaConfigT(TypedDict):
    enable: bool
    model_path: str
    context_count: int


class NotifierConfigT(TypedDict):
    webhook_url: str


class ConfigT(TypedDict):
    message_queue: MQConfigT
    database: DatabaseConfigT
    rules: list[RuleT]
    yara: YARAConfigT
    llama: LlamaConfigT
    notifier: NotifierConfigT
