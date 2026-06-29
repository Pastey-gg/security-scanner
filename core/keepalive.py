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


if TYPE_CHECKING:
    from .listener import Listener
    from .runner import Runner


LOGGER: logging.Logger = logging.getLogger(__name__)


class KeepAlive:
    def __init__(self, *, runner: Runner, listener: Listener) -> None:
        self.runner = runner
        self.listener = listener
        self._lock = asyncio.Lock = asyncio.Lock()
        self._background: asyncio.Task[None] | None = None

        self._has_setup: bool = False
        self._closing: bool = False
        self._closed: bool = False
        self._close_event: asyncio.Event = asyncio.Event()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: Any, **kwargs: Any) -> None:
        await self.close()

    async def setup(self) -> None:
        if self._has_setup:
            return

        LOGGER.info("Starting security scanners...")
        await self.runner.connect()
        await self.listener.setup()

        await self.load_scan()
        self._background = asyncio.create_task(self._runner())
        self._background.add_done_callback(self._done)
        self._has_setup = True

        LOGGER.info("Successfully setup security scanners...")

    async def close(self) -> None:
        LOGGER.info("Closing security scanners...")
        self._closing = True

        await self.listener.close()
        await self.runner.close()

        self._closed = True
        self._close_event.set()

    def reset(self) -> None:
        self._background = None
        self._has_setup = False
        self._closing = False
        self._closed = False

    async def run(self) -> None:
        if self._has_setup:
            raise RuntimeError("Keepalive is currently running.")

        await self.setup()
        await self._close_event.wait()

    def _done(self, future: asyncio.Future[None]) -> None:
        if not self._closing or not self._closed:
            self.reset()
            # return await self.setup()

    async def _runner(self) -> None:
        while True:
            if not self.runner._last_scan or datetime.datetime.now(
                tz=datetime.UTC
            ) > self.runner._last_scan + datetime.timedelta(minutes=30):
                LOGGER.info("Last scan expired... Running security pipelines.")
                pastes = await self.runner.fetch_unscanned(dt=self.runner._last_scan)

                for paste in pastes:
                    try:
                        await self.runner.run_pipeline(paste, save=False)
                    except Exception as e:
                        LOGGER.warning("Error running pipeline: %s", e)

                await self.save_scan(dt=self.runner._last_scan)
            await asyncio.sleep(60)

    async def save_scan(self, *, dt: datetime.datetime | None = None) -> None:
        LOGGER.info("Saving last scan.")
        dt = dt or datetime.datetime.now(tz=datetime.UTC)

        async with self._lock:
            with open(".lastscan", "w") as fp:
                fp.write(dt.isoformat())

    async def load_scan(self) -> None:
        LOGGER.info("Loading last scan.")
        async with self._lock:
            try:
                fp = open(".lastscan")  # noqa: SIM115
            except FileNotFoundError:
                return

            dts = fp.read()
            if dts:
                self.runner._last_scan = datetime.datetime.fromisoformat(dts)

            fp.close()
