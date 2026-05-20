"""Process-wide coordination (shutdown flags, etc.)."""

import threading

shutdown_event = threading.Event()
collect_now_event = threading.Event()


def request_shutdown() -> None:
    """Signal all background loops to stop cleanly."""
    shutdown_event.set()
    collect_now_event.set()  # unblock any waiting collector too


def request_collect_now() -> None:
    """Wake up the collector loop to run immediately."""
    collect_now_event.set()

