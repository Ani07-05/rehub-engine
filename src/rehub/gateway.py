import asyncio
import contextlib
from collections.abc import Awaitable, Callable

CHUNK = 1 << 16
CONNECT_TIMEOUT = 5.0
MAX_CONNECTIONS = 256


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(CHUNK):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        pass


def make_handler(
    host: str, port: int, limit: asyncio.Semaphore
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        async with limit:
            server_w: asyncio.StreamWriter | None = None
            try:
                server_r, upstream_w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), CONNECT_TIMEOUT
                )
                server_w = upstream_w
                await asyncio.gather(_pipe(client_r, upstream_w), _pipe(server_r, client_w))
            except (TimeoutError, OSError):
                pass
            finally:
                for w in (server_w, client_w):
                    if w is not None:
                        w.close()
                        with contextlib.suppress(Exception):
                            await w.wait_closed()

    return handle


async def serve_gateway(
    listen_host: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    ready: asyncio.Future[int] | None = None,
) -> None:
    limit = asyncio.Semaphore(MAX_CONNECTIONS)
    server = await asyncio.start_server(
        make_handler(upstream_host, upstream_port, limit), listen_host, listen_port
    )
    if ready is not None:
        ready.set_result(server.sockets[0].getsockname()[1])
    async with server:
        await server.serve_forever()


def parse_hostport(value: str, default_port: int) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep:
        return value, default_port
    if not port.isdigit():
        raise ValueError(f"invalid port in {value!r}")
    return host or "0.0.0.0", int(port)
