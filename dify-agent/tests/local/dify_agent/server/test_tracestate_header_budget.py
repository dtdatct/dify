"""Regression guard for the inbound ``tracestate`` parsing budget.

The Dify Agent run server is instrumented at the ASGI/FastAPI boundary
(``dify_agent.server.observability``), so a request that carries a ``traceparent``
header also hands an attacker-controlled ``tracestate`` header to
``opentelemetry.trace.propagation.tracecontext.TraceContextTextMapPropagator.extract``,
which is what the default ``OTEL_PROPAGATORS`` (``tracecontext,baggage``) installs.

``opentelemetry-api`` before 1.45.1 split that header with an unbounded
optional-whitespace prefix (``re.split(r"[ \\t]*,[ \\t]*", header)``), which costs
O(N^2) CPU, and applied no length limit first: a ~100 KB ``tracestate`` of whitespace
kept the handling worker busy for seconds, and under asyncio that blocks every other
connection for the duration (GHSA-xcq7-p3pf-p88h / CVE-2026-114603). Version 1.45.1
replaced the split with ``str.split(",")`` plus ``str.strip`` and discards
``tracestate`` headers whose combined length exceeds 8192 characters
(opentelemetry-python#5746).

These tests pin the observable contract rather than the implementation: a hostile
header must be rejected without being parsed, a valid header must still propagate, and
the installed ``opentelemetry-api`` must be outside the affected range.
"""

from __future__ import annotations

import logging
import time
from importlib.metadata import version

import pytest
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# The advisory is fixed in 1.45.1; anything earlier is affected.
_FIRST_FIXED_VERSION = (1, 45, 1)

# 8192 characters is the limit 1.45.1 enforces on the combined tracestate value.
_LIMIT = 8192

_TRACEPARENT = "00-" + "1" * 32 + "-" + "2" * 16 + "-01"


@pytest.fixture(autouse=True)
def _silence_tracestate_parser_logs() -> None:
    """Keep hostile payloads out of test output.

    The affected parser logs the whole offending member at WARNING before giving up,
    which would print the 8 KB test payload into CI output.
    """
    logging.getLogger("opentelemetry.trace.span").setLevel(logging.CRITICAL)


def _parsed_trace_state(tracestate: str):
    """Run the real propagator over one carrier and return the parsed trace state."""
    carrier = {"traceparent": _TRACEPARENT, "tracestate": tracestate}
    context = TraceContextTextMapPropagator().extract(carrier)
    return trace.get_current_span(context).get_span_context().trace_state


def _oversized_but_valid_header() -> str:
    """Build a syntactically valid tracestate longer than the enforced limit.

    Every member matches the W3C ``key=value`` grammar, so the parser cannot bail out
    early on a malformed member: the only thing that can reject this header is the
    length limit itself.
    """
    member = "k" + "a" * 240 + "=" + "v" * 250
    header = ",".join(f"k{index}{member[1:]}" for index in range(17))
    assert len(header) > _LIMIT, "test fixture must exceed the tracestate length limit"
    return header


def _version_tuple(package: str) -> tuple[int, ...]:
    numbers = "".join(char if char.isdigit() or char == "." else " " for char in version(package)).split()
    head = numbers[0].split(".") if numbers else []
    return tuple(int(part) for part in head if part)


def test_oversized_tracestate_is_rejected_without_being_parsed() -> None:
    """A valid but oversized header must not yield trace state."""
    trace_state = _parsed_trace_state(_oversized_but_valid_header())

    assert trace_state is None or len(trace_state) == 0


def test_whitespace_flood_tracestate_is_handled_in_bounded_time() -> None:
    """A whitespace flood must be rejected in bounded time, not parsed quadratically."""
    flood = "a=b" + " " * (128 * 1024) + "c=d"

    started = time.perf_counter()
    trace_state = _parsed_trace_state(flood)
    elapsed = time.perf_counter() - started

    assert trace_state is None or len(trace_state) == 0
    # 1.45.1 rejects on the length check in microseconds; the affected versions take
    # multiple seconds for this payload, so this bound is a wide safety margin.
    assert elapsed < 1.0, f"tracestate flood took {elapsed:.2f}s"


def test_valid_tracestate_still_propagates() -> None:
    """The hardening must not discard legitimate trace state."""
    trace_state = _parsed_trace_state("k1=v1,k2=v2")

    assert trace_state is not None
    assert dict(trace_state.items()) == {"k1": "v1", "k2": "v2"}


@pytest.mark.parametrize("package", ["opentelemetry-api"])
def test_installed_opentelemetry_api_is_outside_the_affected_range(package: str) -> None:
    """The resolved lock must be at or above the first fixed release."""
    assert _version_tuple(package) >= _FIRST_FIXED_VERSION, (
        f"{package} {version(package)} is affected by GHSA-xcq7-p3pf-p88h / CVE-2026-114603"
    )
