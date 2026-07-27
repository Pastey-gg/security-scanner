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

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .enums import *


if TYPE_CHECKING:
    from pika.adapters import blocking_connection
    from pika.spec import Basic, BasicProperties

    from pipelines.base import ScanResult
    from types_.pastes import FilePaste

    from .worker import Worker


LOGGER: logging.Logger = logging.getLogger(__name__)


class Handler:
    def __init__(self, worker: Worker) -> None:
        self.worker = worker

    def __call__(
        self,
        channel: blocking_connection.BlockingChannel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ) -> None:

        if not body:
            LOGGER.warning("Message handler received bad message: No body.")
            channel.basic_reject(method.delivery_tag, requeue=False)
            return

        paste_id = body.decode()
        paste: list[FilePaste] | None = self.fetch_paste(paste_id)

        if not paste:
            LOGGER.warning("Message handler unable to find paste: %s.", paste_id)
            channel.basic_reject(method.delivery_tag, requeue=False)
            return

        try:
            LOGGER.info("Starting scan for '%s'.", paste_id)
            self.wrap_scan(paste)
            LOGGER.info("Processing scan for '%s' completed successfully.", paste_id)
        except Exception as e:
            LOGGER.error("Unable to process scan for '%s' - %s:\n", paste_id, e, exc_info=e)
            channel.basic_reject(method.delivery_tag)
        else:
            # TODO: Notifier...
            channel.basic_ack(method.delivery_tag)

    def wrap_scan(self, paste: list[FilePaste]) -> None:
        for file in paste:
            result = self.scan(file)

            if result:
                return self.process_result(result)

    def scan(self, file: FilePaste) -> ScanResult | None:
        for runner in self.worker.runners:
            result = runner.scan(file)

            if not result:
                continue

            if result.status is not ScanStatus.clear:
                return result

    def process_result(self, result: ScanResult) -> None:
        if result.status is ScanStatus.clear:
            return

        if result.status is ScanStatus.review:
            LOGGER.info("Manual review required for '%s'.", result.paste_id)
            return

        LOGGER.info(
            "Removing paste '%s': %s (Scanner=%s, Severity=%s).",
            result.paste_id,
            result.reason,
            result.service,
            result.severity,
        )
        self.remove_paste(result.paste_id)

    def remove_paste(self, paste_id: str) -> None:
        assert self.worker.pool

        query = """DELETE FROM pastes WHERE id = (%s)"""
        with self.worker.pool.connection() as conn, conn.cursor() as cursor:
            cursor.execute(query, (paste_id,))

    def fetch_paste(self, paste_id: str) -> list[FilePaste] | None:
        assert self.worker.pool

        query = """
        SELECT
            f.id,
            f.paste_id,
            p.created_at,
            p.deleted_at,
            p.web,
            f.name,
            f."language",
            f."content",
            p.deleted_at,
            f.character_count,
            f.line_count
        FROM public.files f
        JOIN public.pastes p
        ON p.id = f.paste_id WHERE paste_id = (%s)"""

        with self.worker.pool.connection() as conn, conn.cursor() as cursor:
            cursor.execute(query, (paste_id,))
            row: list[FilePaste] | None = cursor.fetchall()

        return row
