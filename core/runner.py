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

import asyncio
import datetime
import logging
from typing import TYPE_CHECKING, Any, Self

import asyncpg

import pipeline
from types_.pastes import FileRecord, PasteRecord, PasteT

from .config import CONFIG


if TYPE_CHECKING:
    from .keepalive import KeepAlive


LOGGER: logging.Logger = logging.getLogger(__name__)
type PoolT = asyncpg.Pool[asyncpg.Record]


class Runner:
    keepalive: KeepAlive
    pool: PoolT

    def __init__(self) -> None:
        self._running_event = asyncio.Event()
        self._closing: bool = False
        self._last_scan: datetime.datetime | None = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: Any, **kwargs: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        LOGGER.info("Attempting to connect to Database pool")
        self.pool = await asyncpg.create_pool(CONFIG["general"]["dsn"])

    async def close(self) -> None:
        LOGGER.info("Closing security Runner.")

        pool: PoolT | None = getattr(self, "pool", None)
        if not pool:
            return

        await self._running_event.wait()
        self._closing = True

        try:
            async with asyncio.timeout(10):
                await pool.close()
        except TimeoutError:
            LOGGER.debug("Unable to gracefully close pool. Forcefully terminating...")
            pool.terminate()
        except Exception as e:
            LOGGER.warning("Unable to gracefully close pool: %s", e)

    async def remove_paste(self, paste: PasteT | PasteRecord) -> None:
        LOGGER.info("Paste %s is being removed after failing pipeline.", paste["id"])
        query = """UPDATE pastes deleted_at = $1 WHERE id = $1"""

        async with self.pool.acquire() as conn:
            await conn.execute(query, paste["id"])

    async def gather(self, paste: PasteT | PasteRecord) -> list[FileRecord]:
        query = """SELECT * FROM files WHERE paste_id = $1"""

        async with self.pool.acquire() as conn:
            files = await conn.fetch(query, paste["id"], record_class=FileRecord)

        return files

    async def fetch_unscanned(self, *, dt: datetime.datetime) -> list[PasteRecord]:
        query = """SELECT * FROM pastes WHERE created_at > $1 AND deleted_at = null"""

        async with self.pool.acquire() as conn:
            pastes: list[PasteRecord] = await conn.fetch(query, dt, record_class=PasteRecord)

        return pastes

    async def run_pipeline(self, paste: PasteT | PasteRecord, /, *, save: bool = False) -> None:
        LOGGER.info("Running security pipeline for %s", paste["id"])

        if self._closing:
            return

        self._running_event.clear()
        self._last_scan = datetime.datetime.now(tz=datetime.UTC)
        if save:
            await self.keepalive.save_scan(dt=self._last_scan)

        should_continue: bool = True
        files: list[FileRecord] = await self.gather(paste)
        should_continue = await asyncio.to_thread(self.run_scanners, files)

        if not should_continue:
            await self.remove_paste(paste)

        self._running_event.set()

    def run_scanners(self, files: list[FileRecord]) -> bool:
        for file in files:
            for scanner in pipeline.SCANNERS:
                inst = scanner(file)
                inst.scan()

                if not inst.passes():
                    return False

        return True
