"""Per-thread command tracer — logs every external tool invocation."""
import threading, shlex

_local = threading.local()


def set_tracer(fn):
    _local.fn = fn


def clear_tracer():
    _local.fn = None


def trace(cmd):
    fn = getattr(_local, "fn", None)
    if fn and cmd:
        fn(shlex.join(cmd) if isinstance(cmd, list) else str(cmd))
