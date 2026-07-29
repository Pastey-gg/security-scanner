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
import math
import multiprocessing
import os
import pathlib
from typing import TYPE_CHECKING, Any

import numpy as np
from llama_cpp import Llama

from core import CONFIG
from core.enums import *

from ._policies import *
from .base import BaseScanner, ScanResult


if TYPE_CHECKING:
    from types_.pastes import FilePaste


LOGGER: logging.Logger = logging.getLogger(__name__)
SEVERITY_RANK: dict[Any, int] = {ScanSeverity.moderate: 1, ScanSeverity.high: 2, ScanSeverity.critical: 3}
CHARS_PER_TOKEN_CEILING: int = 8


def available_cores() -> int:
    try:
        quota, period = pathlib.Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if quota != "max":
            return max(1, int(int(quota) / int(period)))
    except OSError, ValueError:
        pass

    try:
        quota_us = int(pathlib.Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text())
        period_us = int(pathlib.Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text())

        if quota_us > 0 and period_us > 0:
            return max(1, int(quota_us / period_us))

    except OSError, ValueError:
        pass

    try:
        return max(1, len(os.sched_getaffinity(0)))
    except AttributeError:
        return max(1, multiprocessing.cpu_count())


class LlamaScanner(BaseScanner):
    PRIORITY = 3
    SERVICE = ScanService.LLAMA
    FAILED_CATEGORIES = tuple(c.code.lower() for c in POLICY if c.action is ScanStatus.fail)
    SEVERE_CATEGORIES = tuple(c.code.lower() for c in POLICY if c.severity is ScanSeverity.critical)

    def __init__(self) -> None:
        self._enabled: bool = False
        self.llama: Llama | None = None
        self.ctx_count: int = 4096
        self.max_chunks: int = 2
        self.max_scan_chars: int = 262_144
        self.threshold_offset: float = 0.0
        self._prompt_overhead: int = 0

        self._safe_id: int = -1
        self._unsafe_id: int = -1
        self._fast_path: bool = False
        self._min_floor: float = min(c.min_probability for c in POLICY)

    def compile(self) -> None:
        self._enabled = CONFIG["llama"]["enable"]
        if not self._enabled:
            return

        fp = pathlib.Path(CONFIG["llama"]["model_path"])
        if not fp.exists():
            LOGGER.warning("Llama AI-Guard missing configuration for model path.")
            self._enabled = False
            return

        self.ctx_count = CONFIG["llama"].get("context_count") or self.ctx_count
        self.max_chunks = CONFIG["llama"].get("max_chunks", self.max_chunks)
        self.max_scan_chars = CONFIG["llama"].get("max_scan_chars", self.max_scan_chars)
        self.threshold_offset = CONFIG["llama"].get("threshold_offset", 0.0)

        cores = available_cores()
        n_threads = CONFIG["llama"].get("threads") or max(cores // 2, 1)
        n_threads_batch = CONFIG["llama"].get("threads_batch") or n_threads

        self.llama = Llama(
            model_path=str(fp),
            n_ctx=self.ctx_count,
            n_gpu_layers=0,
            n_threads=n_threads,
            n_threads_batch=n_threads_batch,
            verbose=False,
        )

        self._resolve_decision_tokens()
        self._prompt_overhead = len(self.llama.tokenize(self.build_prompt("").encode(), add_bos=False, special=True))

        if self._prompt_overhead > self.ctx_count // 2:
            LOGGER.warning(
                "Llama Guard policy uses %d of %d context tokens; consider raising context_count.",
                self._prompt_overhead,
                self.ctx_count,
            )

        LOGGER.info(
            "Successfully setup Llama-Guard AI Scanner (ctx=%d, policy=%d cats, overhead=%d tokens, "
            "threads=%d/%d of %d cores, fast_path=%s).",
            self.ctx_count,
            len(POLICY),
            self._prompt_overhead,
            n_threads,
            n_threads_batch,
            cores,
            self._fast_path,
        )

    def _resolve_decision_tokens(self) -> None:
        assert self.llama is not None

        safe = self.llama.tokenize(b"safe", add_bos=False, special=False)
        unsafe = self.llama.tokenize(b"unsafe", add_bos=False, special=False)

        self._safe_id = safe[0] if safe else -1
        self._unsafe_id = unsafe[0] if unsafe else -1

        self._fast_path = (
            self._safe_id >= 0
            and self._unsafe_id >= 0
            and self._safe_id != self._unsafe_id
            and hasattr(self.llama, "_ctx")
            and hasattr(self.llama._ctx, "get_logits_ith")
        )

        if not self._fast_path:
            LOGGER.warning(
                "Llama Guard could not resolve decision tokens; falling back to generated labels. "
                "Per-category probability floors will behave as on/off switches."
            )

    def render_categories(self) -> str:
        blocks: list[str] = []

        for index, cat in enumerate(POLICY, start=1):
            lines = [f"S{index}: {cat.title}."]

            if cat.should_not:
                lines.append("Should not")
                lines.extend(f"- {item}" for item in cat.should_not)
            if cat.can:
                lines.append("Can")
                lines.extend(f"- {item}" for item in cat.can)

            blocks.append("\n".join(lines))

        return "\n".join(blocks)

    def build_prompt(self, content: str) -> str:
        return PROMPT_TEMPLATE.format(categories=self.render_categories(), content=content)

    def chunk_content(self, content: str) -> list[str]:
        assert self.llama is not None

        budget = self.ctx_count - self._prompt_overhead - 32
        if budget < 256:
            LOGGER.warning("Llama Guard context too small for the configured policy; widen context_count.")
            budget = 256

        ceiling = min(budget * self.max_chunks * CHARS_PER_TOKEN_CEILING, self.max_scan_chars)
        if len(content) > ceiling:
            LOGGER.info("Truncating paste from %d to %d chars before Llama Guard scan.", len(content), ceiling)
            content = content[:ceiling]

        tokens = self.llama.tokenize(content.encode(errors="ignore"), add_bos=False)
        if len(tokens) <= budget:
            return [content]

        chunks: list[str] = []
        for start in range(0, len(tokens), budget):
            if len(chunks) >= self.max_chunks:
                break

            piece = self.llama.detokenize(tokens[start : start + budget])
            chunks.append(piece.decode(errors="ignore"))

        return chunks

    def _eval_with_prefix_reuse(self, tokens: list[int]) -> None:
        assert self.llama is not None

        cached = self.llama.input_ids[: self.llama.n_tokens].tolist()
        common = Llama.longest_token_prefix(cached, tokens)
        common = max(0, min(common, len(tokens) - 1))

        self.llama.n_tokens = common
        self.llama.eval(tokens[common:])

    def decision_probability(self, prompt: str) -> float | None:
        assert self.llama is not None

        if not self._fast_path:
            return None

        tokens = self.llama.tokenize(prompt.encode("utf-8"), add_bos=False, special=True)
        if len(tokens) >= self.ctx_count:
            raise ValueError(f"prompt of {len(tokens)} tokens exceeds context of {self.ctx_count}")

        self._eval_with_prefix_reuse(tokens)

        logits = np.ctypeslib.as_array(self.llama._ctx.get_logits_ith(-1), shape=(self.llama.n_vocab(),))
        safe_logit = float(logits[self._safe_id])
        unsafe_logit = float(logits[self._unsafe_id])

        ceiling = max(safe_logit, unsafe_logit)
        safe_p = math.exp(safe_logit - ceiling)
        unsafe_p = math.exp(unsafe_logit - ceiling)

        return unsafe_p / (safe_p + unsafe_p)

    def classify_categories(self, prompt: str) -> tuple[float, set[str]]:
        assert self.llama is not None

        resp = self.llama.create_completion(
            prompt=prompt,
            max_tokens=16,
            temperature=0.0,
            stop=["<|eot_id|>"],
        )

        if not isinstance(resp, dict):
            raise ValueError(f"Llama Guard returned an unknown resp type. Expected dict got {type(resp)}.")

        text: str = (resp["choices"][0].get("text") or "").strip()
        if not text:
            raise ValueError("empty response")

        probability = 1.0 if text.splitlines()[0].strip().lower() == "unsafe" else 0.0
        return probability, self.parse_categories(text)

    def parse_categories(self, output: str) -> set[str]:
        lines = [line.strip() for line in output.strip().splitlines() if line.strip()]

        if len(lines) < 2:
            return set()

        found: set[str] = set()
        for raw in lines[1].split(","):
            key = raw.strip().lower()

            if canonical := CODE_BY_INDEX.get(key):
                found.add(canonical)
            else:
                LOGGER.debug("Llama Guard returned an unknown category token: %r", raw)

        return found

    def evaluate(self, content: str) -> tuple[float, set[str]]:
        prompt = self.build_prompt(content)
        floor = min(max(self._min_floor + self.threshold_offset, 0.05), 0.99)

        probability = self.decision_probability(prompt)
        if probability is not None and probability < floor:
            return probability, set()

        generated_probability, categories = self.classify_categories(prompt)
        if probability is None:
            probability = generated_probability

        return probability, categories

    def scan(self, file: FilePaste) -> ScanResult | None:
        if not self._enabled or not self.llama:
            return None

        LOGGER.info("Running scan for (%s: %s) with Llama-Guard AI scanner.", file["paste_id"], file["id"])

        best_probability = 0.0
        categories: set[str] = set()

        for chunk in self.chunk_content(file["content"]):
            try:
                probability, found = self.evaluate(chunk)
            except (ValueError, KeyError, IndexError, RuntimeError) as error:
                LOGGER.warning(
                    "Llama Guard AI responded with invalid output (%s, %s): %s",
                    file["paste_id"],
                    file["id"],
                    error,
                )
                continue

            if probability > best_probability:
                best_probability = probability

            categories |= found

        actionable: list[PolicyCategory] = []
        for code in sorted(categories):
            cat = POLICY_BY_CODE.get(code)

            if cat is None:
                LOGGER.debug("Llama Guard returned a category outside the active policy: %s", code)
                continue

            if best_probability >= min(max(cat.min_probability + self.threshold_offset, 0.05), 0.99):
                actionable.append(cat)

        if not actionable:
            LOGGER.info(
                "Llama Guard AI scan passed (%s, %s) p_unsafe=%.3f raw_cats=%s.",
                file["paste_id"],
                file["id"],
                best_probability,
                sorted(categories),
            )
            return None

        action = ScanStatus.fail if any(c.action is ScanStatus.fail for c in actionable) else ScanStatus.review
        severity = max((c.severity for c in actionable), key=lambda s: SEVERITY_RANK.get(s, 0))

        described = ", ".join(f"{c.code.lower()}-{GuardClassifier[c.code.upper()].value}" for c in actionable)
        reason = (
            f"Flagged by Llama Guard AI: [{described}] "
            f"(Action={action}, Severity={severity}, p_unsafe={best_probability:.3f})"
        )
        now = datetime.datetime.now(tz=datetime.UTC)

        return ScanResult(
            status=action,
            service=self.SERVICE,
            severity=severity,
            reason=reason,
            timestamp=now,
            paste_id=file["paste_id"],
            lines=None,
        )
