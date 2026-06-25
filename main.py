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

import core


def main() -> None:
    async def runner() -> None:
        runner = core.Runner()
        listener = core.Listener(runner)
        keep = core.KeepAlive(runner=runner, listener=listener)
        runner.keepalive = keep

        async with keep:
            await keep.run()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        ...


if __name__ == "__main__":
    main()
