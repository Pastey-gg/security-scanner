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
import pathlib
from typing import TYPE_CHECKING, Any

from llama_cpp import CompletionLogprobs, Llama

from core import CONFIG
from core.enums import *

from ._policies import *
from .base import BaseScanner, ScanResult


if TYPE_CHECKING:
    from types_.pastes import FilePaste


LOGGER: logging.Logger = logging.getLogger(__name__)
SEVERITY_RANK: dict[Any, int] = {ScanSeverity.moderate: 1, ScanSeverity.high: 2, ScanSeverity.critical: 3}


class LlamaScanner(BaseScanner):
    PRIORITY = 3
    SERVICE = ScanService.LLAMA
    FAILED_CATEGORIES = tuple(c.code.lower() for c in POLICY if c.action is ScanStatus.fail)
    SEVERE_CATEGORIES = tuple(c.code.lower() for c in POLICY if c.severity is ScanSeverity.critical)

    def __init__(self) -> None:
        self._enabled: bool = False
        self.llama: Llama | None = None
        self.ctx_count: int = 8192
        self.max_chunks: int = 4
        self.threshold_offset: float = 0.0
        self._prompt_overhead: int = 0

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
        self.threshold_offset = CONFIG["llama"].get("threshold_offset", 0.0)

        self.llama = Llama(model_path=str(fp), n_ctx=self.ctx_count, n_gpu_layers=0, logits_all=True, verbose=False)
        self._prompt_overhead = len(self.llama.tokenize(self.build_prompt("").encode(), add_bos=False))

        if self._prompt_overhead > self.ctx_count // 2:
            LOGGER.warning(
                "Llama Guard policy uses %d of %d context tokens; consider raising context_count.",
                self._prompt_overhead,
                self.ctx_count,
            )

        LOGGER.info(
            "Successfully setup Llama-Guard AI Scanner (ctx=%d, policy=%d cats, overhead=%d tokens).",
            self.ctx_count,
            len(POLICY),
            self._prompt_overhead,
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

    def unsafe_probability(self, logprobs: CompletionLogprobs | None) -> float | None:
        if not logprobs:
            return None

        for top in logprobs.get("top_logprobs") or []:
            if not top:
                continue

            safe_p = 0.0
            unsafe_p = 0.0

            for token, logprob in top.items():
                cleaned = token.strip().lower()

                if not cleaned:
                    continue
                if cleaned.startswith("unsafe") or cleaned in {"uns", "un"}:
                    unsafe_p += math.exp(logprob)
                elif cleaned.startswith("safe"):
                    safe_p += math.exp(logprob)

            total = safe_p + unsafe_p

            if total > 0:
                return unsafe_p / total

        return None

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
        assert self.llama is not None

        resp = self.llama.create_completion(
            prompt=self.build_prompt(content),
            max_tokens=48,
            temperature=0.0,
            logprobs=10,
            stop=["<|eot_id|>"],
        )

        if not isinstance(resp, dict):
            raise ValueError("Llama Guard returned an unknown resp type. Excpected dict got '%s'.", type(resp))

        choice = resp["choices"][0]
        text: str = (choice.get("text") or "").strip()

        if not text:
            raise ValueError("empty response")

        probability = self.unsafe_probability(choice.get("logprobs"))
        if probability is None:
            probability = 1.0 if text.splitlines()[0].strip().lower() == "unsafe" else 0.0

        return probability, self.parse_categories(text)

    def scan(self, file: FilePaste) -> ScanResult | None:
        if not self._enabled or not self.llama:
            return None

        LOGGER.info("Running scan for (%s: %s) with Llama-Guard AI scanner.", file["paste_id"], file["id"])

        best_probability = 0.0
        categories: set[str] = set()

        for chunk in self.chunk_content(file["content"]):
            try:
                probability, found = self.evaluate(chunk)
            except (ValueError, KeyError, IndexError) as error:
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
