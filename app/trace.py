"""Trace-event audit of the receive -> pick -> ship lifecycle.

Each event pairs a ``type`` (``receive`` / ``pick`` / ``ship``) with a
``scan`` fed through :func:`app.gs1.parse`; the scan must then contain:

* exactly one AI 01 (GTIN),
* exactly one AI 21 (serial number),
* zero or one AI 10 (batch/lot) -- optional,
* zero or one AI 17 (expiry date) -- optional.

Weight elements (310n/320n) carry no lifecycle meaning and are ignored.
Any parser failure or missing/duplicated AI fails the whole request
with :class:`app.summary.WeightSummaryError` whose ``detail`` names the
offending ``event_index`` -- the same 422 shape as the other endpoints.

Physical items are identified by (GTIN, serial).  Events are applied in
request order to the item's state machine::

    none --receive--> received --pick--> picked --ship--> shipped

Only the exact next transition advances the state; every other event is
recorded as an anomaly and leaves the state untouched:

* ``MISSING_RECEIVE`` -- the item has not been received but the event
  is ``pick`` or ``ship`` (an item's first event must be ``receive``);
* ``DUPLICATE_STAGE`` -- the event repeats the stage the item has
  already completed (e.g. a second ``pick``);
* ``STAGE_REGRESSION`` -- the event names a stage earlier than the
  item's state (e.g. ``receive`` after ``pick``);
* ``STAGE_SKIPPED`` -- the event jumps over an uncompleted stage
  (``ship`` while the item is only ``received``).

Batch (AI 10 raw value, absence included) and expiry (AI 17 raw value)
are item attributes fixed by the item's first event -- anomalous or
not.  A later event that disagrees fails the whole request with
:class:`EventConflictError` whose ``detail`` carries ``event_index``
(the conflicting event) and ``first_index`` (the event that first
defined the item).

The result lists one entry per event in input order with the item state
before and after the event plus its anomaly (``None`` when the
transition was valid), and a ``summary`` counting the physical items
per final state (``none`` / ``received`` / ``picked`` / ``shipped``).
"""

from __future__ import annotations

from .gs1 import GS1ParseError, Element, parse
from .summary import ScanValidationError, WeightSummaryError

REQUIRED_AI_TEXT = (
    "exactly one AI 01 (GTIN), exactly one AI 21 (serial number), "
    "at most one AI 10 (batch/lot), and at most one AI 17 (expiry date)"
)

EVENT_TYPES = ("receive", "pick", "ship")
STATES = ("none", "received", "picked", "shipped")

# Stage level of each event type / state: the one valid transition from a
# state is exactly one level up.
_EVENT_LEVEL = {"receive": 1, "pick": 2, "ship": 3}
_STATE_LEVEL = {"none": 0, "received": 1, "picked": 2, "shipped": 3}
_NEXT_STATE = {"receive": "received", "pick": "picked", "ship": "shipped"}

# The event type each state expects next (for anomaly reporting).
_EXPECTED_NEXT = {
    "none": "'receive'",
    "received": "'pick'",
    "picked": "'ship'",
    "shipped": "no further events (item already shipped)",
}


class EventConflictError(Exception):
    """Two events of one item disagree on batch or expiry.

    ``detail`` is the complete 422 payload: ``event_index`` (the
    conflicting event) and ``first_index`` (the event that first
    defined the item) plus the conflict under ``error``.
    """

    def __init__(self, detail: dict):
        super().__init__(detail["error"]["message"])
        self.detail = detail


def _failure(index: int, error: GS1ParseError) -> WeightSummaryError:
    """Wrap a parser/validation error with the offending event index."""
    return WeightSummaryError({"event_index": index, "error": error.to_dict()})


def _extract(
    index: int, elements: list[Element]
) -> tuple[str, str, str | None, str | None]:
    """Pull (GTIN, serial, batch or None, AI 17 or None) from one scan."""
    gtins = [e for e in elements if e.ai == "01"]
    serials = [e for e in elements if e.ai == "21"]
    batches = [e for e in elements if e.ai == "10"]
    expiries = [e for e in elements if e.ai == "17"]

    if len(gtins) != 1:
        if not gtins:
            raise ScanValidationError(
                "MISSING_AI",
                f"event {index}: missing required AI 01 (GTIN)",
                expected=REQUIRED_AI_TEXT,
            )
        raise ScanValidationError(
            "DUPLICATE_AI",
            f"event {index}: AI 01 (GTIN) appears {len(gtins)} times; exactly one is required",
            expected="exactly one AI 01 (GTIN)",
            found=f"{len(gtins)} AI 01 elements",
            offset=gtins[1].offset,
        )

    if len(serials) != 1:
        if not serials:
            raise ScanValidationError(
                "MISSING_AI",
                f"event {index}: missing required AI 21 (serial number)",
                expected=REQUIRED_AI_TEXT,
            )
        raise ScanValidationError(
            "DUPLICATE_AI",
            f"event {index}: AI 21 (serial number) appears {len(serials)} times; exactly one is required",
            expected="exactly one AI 21 (serial number)",
            found=f"{len(serials)} AI 21 elements",
            offset=serials[1].offset,
        )

    if len(batches) > 1:
        raise ScanValidationError(
            "DUPLICATE_AI",
            f"event {index}: AI 10 (batch/lot) appears {len(batches)} times; at most one is allowed",
            expected="at most one AI 10 (batch/lot)",
            found=f"{len(batches)} AI 10 elements",
            offset=batches[1].offset,
        )

    if len(expiries) > 1:
        raise ScanValidationError(
            "DUPLICATE_AI",
            f"event {index}: AI 17 (expiry date) appears {len(expiries)} times; at most one is allowed",
            expected="at most one AI 17 (expiry date)",
            found=f"{len(expiries)} AI 17 elements",
            offset=expiries[1].offset,
        )

    return (
        gtins[0].value,
        serials[0].value,
        batches[0].value if batches else None,
        expiries[0].value if expiries else None,
    )


def _batch_text(batch: str | None) -> str:
    return f"batch {batch!r}" if batch is not None else "no batch (AI 10 absent)"


def _expiry_text(expiry: str | None) -> str:
    return f"expiry {expiry!r}" if expiry is not None else "no expiry (AI 17 absent)"


def _conflict(index: int, item: dict, code: str, first_text: str, current_text: str):
    first_index = item["index"]
    raise EventConflictError(
        {
            "event_index": index,
            "first_index": first_index,
            "error": {
                "error": code,
                "message": (
                    f"event {index}: item GTIN '{item['gtin']}' serial "
                    f"'{item['serial']}' was first seen at event "
                    f"{first_index} with {first_text}, but this event has "
                    f"{current_text}"
                ),
                "expected": f"{first_text} (event {first_index})",
                "found": current_text,
            },
        }
    )


def _check_consistent(
    index: int, item: dict, batch: str | None, expiry: str | None
) -> None:
    """Reject an event whose item attributes disagree with the first event."""
    if batch != item["batch"]:
        _conflict(
            index,
            item,
            "CONFLICTING_BATCH",
            _batch_text(item["batch"]),
            _batch_text(batch),
        )
    if expiry != item["expiry"]:
        _conflict(
            index,
            item,
            "CONFLICTING_EXPIRY",
            _expiry_text(item["expiry"]),
            _expiry_text(expiry),
        )


def _transition(index: int, item: dict, event_type: str) -> dict | None:
    """Apply one event to the item's state machine.

    Advances the state and returns ``None`` for the one valid
    transition; otherwise returns the anomaly dict and leaves the
    state untouched.
    """
    state = item["state"]
    current = _STATE_LEVEL[state]
    level = _EVENT_LEVEL[event_type]
    if level == current + 1:
        item["state"] = _NEXT_STATE[event_type]
        return None

    gtin, serial = item["gtin"], item["serial"]
    if current == 0:
        code = "MISSING_RECEIVE"
        message = (
            f"event {index}: item GTIN '{gtin}' serial '{serial}' has not "
            "been received; an item's first event must be 'receive', "
            f"found '{event_type}'"
        )
    elif level == current:
        code = "DUPLICATE_STAGE"
        message = (
            f"event {index}: item GTIN '{gtin}' serial '{serial}' has "
            f"already completed stage '{event_type}' (state '{state}'); "
            "a completed stage cannot be repeated"
        )
    elif level < current:
        code = "STAGE_REGRESSION"
        message = (
            f"event {index}: item GTIN '{gtin}' serial '{serial}' is in "
            f"state '{state}'; '{event_type}' is an earlier stage and "
            "cannot be re-entered"
        )
    else:
        prerequisite = EVENT_TYPES[level - 2]
        code = "STAGE_SKIPPED"
        message = (
            f"event {index}: item GTIN '{gtin}' serial '{serial}' is in "
            f"state '{state}'; '{event_type}' requires a prior "
            f"'{prerequisite}' event"
        )
    return {
        "error": code,
        "message": message,
        "expected": _EXPECTED_NEXT[state],
        "found": event_type,
    }


def audit(events: list[tuple[str, str]]) -> dict:
    """Apply an ordered trace-event stream to the per-item state machines.

    ``events`` is a list of ``(type, scan)`` pairs in order of
    occurrence, with ``type`` one of ``receive`` / ``pick`` / ``ship``
    and ``scan`` a raw GS1 element string or Digital Link URI.

    Returns ``{"events": [...], "summary": {...}}`` with one event entry
    per input event in the same order (``event_index``, echoed ``type``,
    ``gtin``, ``serial``, ``state_before``, ``state_after`` and
    ``anomaly`` -- ``None`` for a valid transition) and ``summary``
    mapping every state (``none`` / ``received`` / ``picked`` /
    ``shipped``) to the number of physical items ending in it.
    """
    items: dict[tuple[str, str], dict] = {}
    results = []
    for index, (event_type, scan) in enumerate(events):
        try:
            elements = parse(scan)
        except GS1ParseError as exc:
            raise _failure(index, exc) from exc
        try:
            gtin, serial, batch, expiry = _extract(index, elements)
        except ScanValidationError as exc:
            raise _failure(index, exc) from exc

        key = (gtin, serial)
        item = items.get(key)
        if item is None:
            item = {
                "index": index,
                "gtin": gtin,
                "serial": serial,
                "batch": batch,
                "expiry": expiry,
                "state": "none",
            }
            items[key] = item
        else:
            _check_consistent(index, item, batch, expiry)

        state_before = item["state"]
        anomaly = _transition(index, item, event_type)
        results.append(
            {
                "event_index": index,
                "type": event_type,
                "gtin": gtin,
                "serial": serial,
                "state_before": state_before,
                "state_after": item["state"],
                "anomaly": anomaly,
            }
        )

    summary = {state: 0 for state in STATES}
    for item in items.values():
        summary[item["state"]] += 1
    return {"events": results, "summary": summary}
