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
import json
import logging
from typing import TYPE_CHECKING, Any

import asyncpg

from .config import CONFIG


if TYPE_CHECKING:
    from types_.pastes import PasteRecordT

    from .runner import Runner


LOGGER: logging.Logger = logging.getLogger(__name__)


class Listener:
    def __init__(self, runner: Runner, /) -> None:
        self.runner = runner
        self.connection: asyncpg.Connection | None = None
        self._setup: bool = False

    def is_setup(self) -> bool:
        """Checks whether the listener has been setup."""
        return self._setup

    def is_alive(self) -> bool:
        """Checks whether the connection is currently active."""
        return self.connection is not None and not self.connection.is_closed()

    async def setup(self) -> None:
        """Opens the connection and assigns a listener."""
        if self.connection or self._setup:
            raise RuntimeError(f"{self!r} has already been setup.")

        LOGGER.info("Setting-up Security Listener.")

        dsn = CONFIG["general"]["dsn"]
        event = CONFIG["general"]["event_name"]

        self.connection = await asyncpg.connect(dsn)
        await self.connection.add_listener(event, self.callback)  # type: ignore

    async def callback(self, conn: asyncpg.Connection[Any], pid: int, channel: str, payload: str) -> None:
        data: PasteRecordT = json.loads(payload)
        paste = data["record"]

        LOGGER.info("Received paste from listener: %s")
        await self.runner.run_pipeline(paste)

    async def close(self) -> None:
        """Closes and resets the listener state."""
        if not self.connection:
            return

        LOGGER.info("Closing Security Listener.")

        try:
            async with asyncio.timeout(10):
                await self.connection.close()
        except TimeoutError:
            self.connection.terminate()
        except Exception as e:
            LOGGER.warning("Unable to gracefully close database connection: %s", e)

        self.reset()
        LOGGER.info("Successfully closed and reset %r", self)

    def reset(self) -> None:
        """Resets the state of the listener. This does not close any active connections."""
        self._setup = False
        self.connection = None
