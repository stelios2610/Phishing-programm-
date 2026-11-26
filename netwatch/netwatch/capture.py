"""Optional ICMP echo listener. It records only the sender of pings to this host."""

from __future__ import annotations

import select
import socket
import threading
from collections import deque

from netwatch.parse import icmp_echo_source


class IcmpEchoTap:
    def __init__(self) -> None:
        self.mode = "counters"
        self._sock: socket.socket | None = None
        self._closed = threading.Event()
        self._sources: deque[str] = deque(maxlen=50)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setblocking(False)
        except OSError:
            return
        self._sock = sock
        self.mode = "icmp-echo"
        self._thread = threading.Thread(target=self._run, name="netwatch-icmp", daemon=True)
        self._thread.start()

    def drain(self) -> list[str]:
        with self._lock:
            found = list(self._sources)
            self._sources.clear()
            return found

    def close(self) -> None:
        self._closed.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None

    def _run(self) -> None:
        while not self._closed.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                ready, _, _ = select.select([sock], [], [], 0.5)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                packet, _addr = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            source = icmp_echo_source(packet)
            if source is None:
                continue
            with self._lock:
                self._sources.append(source)
