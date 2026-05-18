"""Process-wide coordination (shutdown flags, etc.)."""
import threading

shutdown_event = threading.Event()


def request_shutdown() -> None:
    """Signal all background loops to stop cleanly."""
    shutdown_event.set()
