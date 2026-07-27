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
from typing import TYPE_CHECKING, Any, Self

import pika
from psycopg import Connection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from pipelines import _SCANNERS

from .config import CONFIG
from .handler import Handler


if TYPE_CHECKING:
    from pika.adapters import blocking_connection

    from pipelines import BaseScanner


LOGGER: logging.Logger = logging.getLogger(__name__)


class Worker:
    def __init__(self) -> None:
        self.connection: pika.BlockingConnection | None = None
        self.channel: blocking_connection.BlockingChannel | None = None
        self.pool: ConnectionPool[Any] | None = None
        self._runners: list[BaseScanner] = []

        self._setup: bool = False
        self._running: bool = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        self.close()

    @property
    def runners(self) -> list[BaseScanner]:
        return self._runners

    def setup(self) -> None:
        LOGGER.info("Compiling scanners...")

        for obj in _SCANNERS:
            scanner = obj()
            scanner.compile()

            self._runners.append(scanner)

        self._runners.sort(key=lambda s: s.PRIORITY)
        self._setup = True

    def run(self) -> None:
        LOGGER.info("Attempting to start worker for incoming message processing.")

        if self._running:
            return

        if not self._setup:
            self.setup()

        config = CONFIG["message_queue"]
        host = config["host"]
        port = config["port"]

        dsn = CONFIG["database"]["dsn"]
        self.pool = ConnectionPool(
            dsn,
            check=ConnectionPool.check_connection,
            open=True,
            connection_class=Connection[DictRow],
            kwargs={"row_factory": dict_row},
        )

        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=host, port=port))
        self.channel = self.connection.channel()

        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(config["queue_name"], Handler(self))

        self._running = True

        try:
            LOGGER.info("Worker is now listening for incoming messages...")
            self.channel.start_consuming()
        except KeyboardInterrupt:
            LOGGER.warning("Shutting worker down due to KeyboardInterrupt")
        except Exception as e:
            LOGGER.critical("Unhandled exception during worker consuming '%s':\n", e, exc_info=e)

        self.close()

    def close(self) -> None:
        if not self._running:
            return

        if not self.connection:
            return

        if self.channel:
            try:
                self.channel.close()  # type: ignore
            except Exception:
                pass

        if self.pool:
            try:
                self.pool.close()
            except Exception as e:
                LOGGER.debug("Ignoring exception while closing Postgres: %s", e)

        try:
            self.connection.close()
        except Exception as e:
            LOGGER.debug("Unhandled exception closing RMQ connection: %s", e, exc_info=e)

        self._running = False
