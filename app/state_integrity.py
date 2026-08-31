from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator


@contextmanager
def managed_sqlite_connection(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Commit/rollback transaction state and always release the OS handle.

    ``sqlite3.Connection`` as a context manager does not close the connection.
    That distinction is observable on Windows, where an uncollected connection
    can keep WAL/SHM files locked.  Store methods use this owner so connection
    lifetime is deterministic instead of depending on garbage collection.
    """

    try:
        with connection:
            yield connection
    finally:
        connection.close()
