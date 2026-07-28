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

from typing import TYPE_CHECKING

import requests

from .config import CONFIG
from .enums import ScanStatus


if TYPE_CHECKING:
    from pipelines.base import ScanResult
    from types_.pastes import FilePaste


class Notifier:
    def send_notification(self, paste: FilePaste, *, result: ScanResult | None = None) -> None:
        webhook = CONFIG["notifier"]["webhook_url"]
        paste_id = paste["paste_id"]
        web = paste["web"]

        if not result or result.status is ScanStatus.clear:
            colour = 0x198754
            status = "CLEAR"
        else:
            colour = 0xFFED29 if result.status is ScanStatus.review else 0xFF3333
            status = "NEEDS REVIEW" if result.status is ScanStatus.review else "FAILED"

        data = {
            "content": None,
            "embeds": [
                {
                    "title": f"Paste Created - {status}",
                    "description": f"https://pastey.gg/{paste_id}",
                    "color": colour,
                    "footer": {"text": f"Pasted via {'web' if web else 'api'}"},
                    "thumbnail": {"url": "https://pastey.gg/logo.png"},
                }
            ],
            "username": "Pastey.gg",
            "avatar_url": "https://pastey.gg/logo.png",
            "attachments": [],
        }

        resp = requests.post(webhook, json=data)
        resp.raise_for_status()
