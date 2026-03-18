"""
ClawPot process watcher

Monitors target process (OpenClaw) behavior in real time:
- Open files  (via /proc/<pid>/fd)
- Network connections (via /proc/<pid>/net/tcp, tcp6)
- Child processes (via /proc/<pid>/task, /proc)

No third-party dependencies — pure Python standard library + Linux /proc interface.
"""

import os
import re
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Set, List, Optional, Callable

from .logger import ClawPotLogger, Event


def _hex_to_ip(hex_str: str) -> str:
    """Convert a hex IP from /proc/net/tcp to a human-readable address"""
    if len(hex_str) == 8:
        # IPv4: little-endian
        packed = bytes.fromhex(hex_str)
        return socket.inet_ntoa(packed[::-1])
    elif len(hex_str) == 32:
        # IPv6: 4-byte groups, little-endian
        parts = [hex_str[i:i+8] for i in range(0, 32, 8)]
        addr = b"".join(bytes.fromhex(p)[::-1] for p in parts)
        return socket.inet_ntop(socket.AF_INET6, addr)
    return hex_str


def _read_proc_net(pid: int, proto: str) -> List[dict]:
    """
    Read /proc/<pid>/net/<proto> to get network connections.

    Returns: [{"local_ip": ..., "local_port": ..., "remote_ip": ..., "remote_port": ..., "state": ...}]
    """
    net_file = Path(f"/proc/{pid}/net/{proto}")
    if not net_file.exists():
        # Fallback to global
        net_file = Path(f"/proc/net/{proto}")
    if not net_file.exists():
        return []

    connections = []
    try:
        lines = net_file.read_text().splitlines()[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[1].split(":")
            remote = parts[2].split(":")
            state = parts[3]

            if len(local) != 2 or len(remote) != 2:
                continue

            connections.append({
                "local_ip": _hex_to_ip(local[0]),
                "local_port": int(local[1], 16),
                "remote_ip": _hex_to_ip(remote[0]),
                "remote_port": int(remote[1], 16),
                "state": state,
                "proto": proto,
            })
    except (PermissionError, FileNotFoundError, ValueError):
        pass
    return connections


def _read_open_files(pid: int) -> Set[str]:
    """Read open file paths of a process via /proc/<pid>/fd"""
    fd_dir = Path(f"/proc/{pid}/fd")
    paths = set()
    if not fd_dir.exists():
        return paths
    try:
        for fd in fd_dir.iterdir():
            try:
                target = os.readlink(str(fd))
                # Only keep real file paths (exclude sockets, pipes, etc.)
                if target.startswith("/") and not target.startswith("/proc"):
                    paths.add(target)
            except (PermissionError, FileNotFoundError, OSError):
                pass
    except (PermissionError, FileNotFoundError):
        pass
    return paths


def _get_child_pids(pid: int) -> Set[int]:
    """Get all child PIDs of a process"""
    children = set()
    try:
        task_dir = Path(f"/proc/{pid}/task")
        if task_dir.exists():
            for tid_dir in task_dir.iterdir():
                children_file = tid_dir / "children"
                if children_file.exists():
                    content = children_file.read_text().strip()
                    if content:
                        children.update(int(c) for c in content.split())
    except (PermissionError, FileNotFoundError, ValueError):
        pass

    # Also scan /proc for processes whose PPid matches
    try:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            try:
                status = (proc_dir / "status").read_text()
                ppid_match = re.search(r"PPid:\s+(\d+)", status)
                if ppid_match and int(ppid_match.group(1)) == pid:
                    children.add(int(proc_dir.name))
            except (PermissionError, FileNotFoundError, ValueError):
                pass
    except (PermissionError, FileNotFoundError):
        pass

    return children


def _get_proc_name(pid: int) -> str:
    """Get the name of a process"""
    try:
        comm = Path(f"/proc/{pid}/comm")
        if comm.exists():
            return comm.read_text().strip()
    except (PermissionError, FileNotFoundError):
        pass
    return f"pid-{pid}"


def _is_pid_alive(pid: int) -> bool:
    """Check whether a PID is still running"""
    return Path(f"/proc/{pid}").exists()


class ProcessWatcher:
    """
    Process behavior watcher

    Continuously observes a target process's file access and network connections,
    reporting any suspicious behavior to the ClawPotMonitor.
    """

    # System library paths to ignore
    IGNORE_FILE_PREFIXES = (
        "/usr/lib/",
        "/usr/share/",
        "/lib/",
        "/sys/",
        "/dev/",
        "/run/",
    )

    # Local/loopback IPs to ignore
    IGNORE_REMOTE_IPS = {
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
    }

    def __init__(
        self,
        pid: int,
        poll_interval: float = 1.0,
        on_file_access: Optional[Callable[[str], None]] = None,
        on_network_connect: Optional[Callable[[str, int], None]] = None,
        on_child_spawn: Optional[Callable[[int, str], None]] = None,
    ):
        self.pid = pid
        self.process_name = _get_proc_name(pid)
        self.poll_interval = poll_interval
        self.on_file_access = on_file_access
        self.on_network_connect = on_network_connect
        self.on_child_spawn = on_child_spawn

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._seen_files: Set[str] = set()
        self._seen_remotes: Set[str] = set()  # "ip:port"
        self._seen_children: Set[int] = set()

    def start(self):
        """Start the watcher in a background thread"""
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True, name=f"clawpot-watcher-{self.pid}")
        self._thread.start()

    def stop(self):
        """Stop the watcher"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _watch_loop(self):
        """Main polling loop"""
        while self._running and _is_pid_alive(self.pid):
            try:
                self._check_files()
                self._check_network()
                self._check_children()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _check_files(self):
        """Check for newly opened files"""
        current = _read_open_files(self.pid)
        new_files = current - self._seen_files
        self._seen_files = current

        for path in new_files:
            if any(path.startswith(prefix) for prefix in self.IGNORE_FILE_PREFIXES):
                continue
            if self.on_file_access:
                self.on_file_access(path)

    def _check_network(self):
        """Check for new network connections"""
        for proto in ("tcp", "tcp6"):
            connections = _read_proc_net(self.pid, proto)
            for conn in connections:
                remote_ip = conn["remote_ip"]
                remote_port = conn["remote_port"]
                state = conn["state"]

                # Only watch ESTABLISHED (01) connections, skip loopback
                if state != "01":
                    continue
                if remote_ip in self.IGNORE_REMOTE_IPS:
                    continue
                if remote_port == 0:
                    continue

                key = f"{remote_ip}:{remote_port}"
                if key not in self._seen_remotes:
                    self._seen_remotes.add(key)
                    if self.on_network_connect:
                        self.on_network_connect(remote_ip, remote_port)

    def _check_children(self):
        """Check for newly spawned child processes"""
        current = _get_child_pids(self.pid)
        new_children = current - self._seen_children
        self._seen_children = current

        for child_pid in new_children:
            child_name = _get_proc_name(child_pid)
            if self.on_child_spawn:
                self.on_child_spawn(child_pid, child_name)
