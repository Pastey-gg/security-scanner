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

import datetime
import logging
import pathlib
from typing import TYPE_CHECKING

from llama_cpp import Llama

from core import CONFIG
from core.enums import *

from .base import BaseScanner, ScanResult


if TYPE_CHECKING:
    from types_.pastes import FilePaste


LOGGER: logging.Logger = logging.getLogger(__name__)


class LlamaScanner(BaseScanner):
    PRIORITY = 3
    SERVICE = ScanService.LLAMA
    FAILED_CATEGORIES = ("s1", "s3", "s4", "s5", "s6", "s9", "s11")
    SEVERE_CATEGORIES = ("s3", "s4", "s11")

    def __init__(self) -> None:
        self._enabled: bool = False
        self.llama: Llama | None = None
        self.ctx_count: int = 2048

    def compile(self) -> None:
        self._enabled = CONFIG["yara"]["enable"]
        if not self._enabled:
            return

        fp = pathlib.Path(CONFIG["llama"]["model_path"])
        if not fp.exists():
            LOGGER.warning("Llama AI-Guard missing configuration for model path.")
            self._enabled = False
            return

        self.ctx_count = CONFIG["llama"]["context_count"] or self.ctx_count
        self.llama = Llama(model_path=str(fp), n_ctx=self.ctx_count, n_gpu_layers=0, verbose=False)
        LOGGER.info("Successfully setup Llama-Guard AI Scanner...")

    def build_prompt(self, content: str) -> str:
        return f"""<|start_header_id|>user<|end_header_id|>

        Task: Check if there is unsafe content in 'User' messages in pastes for a code sharing platform according to our safety policy with the below categories.

        <BEGIN UNSAFE CONTENT CATEGORIES>
        S1: Violent Crimes.
        S2: Non-Violent Crimes.
        S3: Sex-Related Crimes.
        S4: Child Sexual Exploitation.
        S5: Defamation.
        S6: Specialized Advice.
        S7: Privacy.
        S8: Intellectual Property.
        S9: Indiscriminate Weapons.
        S10: Hate.
        S11: Suicide & Self-Harm.
        S12: Sexual Content.
        S13: Elections.
        <END UNSAFE CONTENT CATEGORIES>

        <BEGIN CONVERSATION>

        User: {content[: self.ctx_count - 500]}

        <END CONVERSATION>

        Provide your safety assessment for ONLY THE LAST User message in the above conversation (code paste):
        - First line must read 'safe' or 'unsafe'.
        - If unsafe, a second line must include a comma-separated list of violated categories.<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    def scan(self, file: FilePaste) -> ScanResult | None:
        if not self._enabled or not self.llama:
            return

        LOGGER.info("Running scan for (%s: %s) with Llama-Guard AI scanner.", file["paste_id"], file["id"])

        prompt = self.build_prompt(file["content"])
        resp = self.llama.create_completion(prompt=prompt, max_tokens=20, temperature=0.0)

        if not isinstance(resp, dict):
            LOGGER.warning("Llama Guard AI responded with invalid output:( %s, %s).", file["paste_id"], file["id"])
            return

        output_str: str = resp["choices"][0]["text"]
        if not output_str:
            LOGGER.warning("Llama Guard AI responded with no output: (%s, %s).", file["paste_id"], file["id"])
            return

        output_str = output_str.removeprefix("\n\n")
        output = output_str.split("\n")
        is_safe = output[0] != "unsafe"
        category = output[1].lower()

        if is_safe or category in ("s8", "s13"):
            LOGGER.info("Llama Guard AI scan passed successfully: (%s, %s).", file["paste_id"], file["id"])
            return

        action = ScanStatus.fail if category in self.FAILED_CATEGORIES else ScanStatus.review
        service = self.SERVICE
        severity = (
            ScanSeverity.critical
            if category in self.SEVERE_CATEGORIES
            else ScanSeverity.high
            if action is ScanStatus.fail
            else ScanSeverity.moderate
        )

        category_enum = GuardClassifier[category.upper()]
        reason = f"Failed on Llama Guard AI: [{category}-{category_enum.value}] (Severity={severity})"
        now = datetime.datetime.now(tz=datetime.UTC)

        return ScanResult(
            status=action,
            service=service,
            severity=severity,
            reason=reason,
            timestamp=now,
            paste_id=file["paste_id"],
            lines=None,
        )
