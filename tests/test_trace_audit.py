"""End-to-end tests for the /trace-audit endpoint."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

GS = "\x1d"
GTIN_OK = "09501101530003"  # valid Mod-10 check digit
GTIN2 = "00000000000017"  # second valid GTIN


def scan(gtin=GTIN_OK, serial="SN1", batch="B1", expiry="250131"):
    """Build an element-string scan with 01/21 and optional 10/17."""
    parts = f"01{gtin}"
    if expiry is not None:
        parts += f"17{expiry}"
    if batch is not None:
        parts += f"10{batch}{GS}"
    parts += f"21{serial}"
    return parts


def ev(type_, **kwargs):
    return {"type": type_, "scan": scan(**kwargs)}


def audit(events):
    return client.post("/trace-audit", json={"events": events})


# ---------------------------------------------------------------- happy path


def test_full_lifecycle_advances_one_stage_per_event():
    resp = audit([ev("receive"), ev("pick"), ev("ship")])
    assert resp.status_code == 200
    body = resp.json()
    assert [e["state_before"] for e in body["events"]] == [
        "none",
        "received",
        "picked",
    ]
    assert [e["state_after"] for e in body["events"]] == [
        "received",
        "picked",
        "shipped",
    ]
    assert [e["anomaly"] for e in body["events"]] == [None, None, None]
    assert body["summary"] == {
        "none": 0,
        "received": 0,
        "picked": 0,
        "shipped": 1,
    }


def test_events_are_reported_in_input_order_with_indices():
    resp = audit([ev("receive", serial="S2"), ev("receive", serial="S1")])
    body = resp.json()
    assert [e["event_index"] for e in body["events"]] == [0, 1]
    assert [e["serial"] for e in body["events"]] == ["S2", "S1"]
    assert [e["type"] for e in body["events"]] == ["receive", "receive"]
    assert all(e["gtin"] == GTIN_OK for e in body["events"])


def test_interleaved_items_have_independent_state_machines():
    resp = audit(
        [
            ev("receive", serial="S1"),
            ev("receive", serial="S2"),
            ev("pick", serial="S1"),
            ev("ship", serial="S2"),  # S2 was never picked: anomaly
            ev("pick", serial="S2"),
            ev("ship", serial="S2"),
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert [e["state_after"] for e in body["events"]] == [
        "received",
        "received",
        "picked",
        "received",  # anomaly: state untouched
        "picked",
        "shipped",
    ]
    assert body["events"][3]["anomaly"]["error"] == "STAGE_SKIPPED"
    assert body["summary"] == {
        "none": 0,
        "received": 0,
        "picked": 1,
        "shipped": 1,
    }


def test_same_serial_under_different_gtins_are_distinct_items():
    resp = audit(
        [ev("receive", serial="SN1"), ev("receive", gtin=GTIN2, serial="SN1")]
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["received"] == 2


def test_optional_ais_may_be_absent():
    resp = audit(
        [
            ev("receive", batch=None, expiry=None),
            ev("pick", batch=None, expiry=None),
        ]
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["picked"] == 1


def test_weight_elements_are_ignored():
    resp = audit(
        [{"type": "receive", "scan": scan() + GS + "3103002000"}]
    )
    assert resp.status_code == 200
    assert resp.json()["events"][0]["state_after"] == "received"


def test_digital_link_scan_accepted():
    resp = audit(
        [
            {
                "type": "receive",
                "scan": "https://id.gs1.org/01/09501101530003/17/250131/21/SN7?10=B1",
            },
            {
                "type": "pick",
                "scan": "https://id.gs1.org/01/09501101530003/17/250131/21/SN7?10=B1",
            },
        ]
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["picked"] == 1


def test_empty_events_give_empty_results_and_zero_summary():
    resp = audit([])
    assert resp.status_code == 200
    assert resp.json() == {
        "events": [],
        "summary": {"none": 0, "received": 0, "picked": 0, "shipped": 0},
    }


def test_response_shape():
    resp = audit([ev("receive")])
    body = resp.json()
    assert set(body) == {"events", "summary"}
    assert set(body["events"][0]) == {
        "event_index",
        "type",
        "gtin",
        "serial",
        "state_before",
        "state_after",
        "anomaly",
    }
    assert set(body["summary"]) == {"none", "received", "picked", "shipped"}


def test_audit_function_direct():
    from app.trace import audit as run

    result = run([("receive", scan()), ("pick", scan())])
    assert result["events"][1]["state_after"] == "picked"
    assert result["summary"] == {
        "none": 0,
        "received": 0,
        "picked": 1,
        "shipped": 0,
    }


# ------------------------------------------------------------------- anomalies


def test_first_event_not_receive_is_an_anomaly():
    for bad_type in ("pick", "ship"):
        resp = audit([ev(bad_type)])
        assert resp.status_code == 200
        (event,) = resp.json()["events"]
        assert event["state_before"] == "none"
        assert event["state_after"] == "none"  # state not advanced
        anomaly = event["anomaly"]
        assert anomaly["error"] == "MISSING_RECEIVE"
        assert anomaly["found"] == bad_type
        assert "receive" in anomaly["expected"]
        assert resp.json()["summary"]["none"] == 1


def test_anomaly_shape():
    resp = audit([ev("pick")])
    anomaly = resp.json()["events"][0]["anomaly"]
    assert set(anomaly) == {"error", "message", "expected", "found"}
    assert "event 0" in anomaly["message"]
    assert GTIN_OK in anomaly["message"]
    assert "SN1" in anomaly["message"]


def test_anomaly_does_not_advance_state_and_later_receive_recovers():
    resp = audit([ev("pick"), ev("receive"), ev("pick"), ev("ship")])
    body = resp.json()
    assert [e["anomaly"] is None for e in body["events"]] == [
        False,
        True,
        True,
        True,
    ]
    assert [e["state_after"] for e in body["events"]] == [
        "none",
        "received",
        "picked",
        "shipped",
    ]
    assert body["summary"]["shipped"] == 1


def test_duplicate_completed_stage_is_an_anomaly():
    resp = audit(
        [
            ev("receive"),
            ev("receive"),  # duplicate receive
            ev("pick"),
            ev("pick"),  # duplicate pick
            ev("ship"),
            ev("ship"),  # duplicate ship
        ]
    )
    body = resp.json()
    codes = [e["anomaly"] and e["anomaly"]["error"] for e in body["events"]]
    assert codes == [None, "DUPLICATE_STAGE", None, "DUPLICATE_STAGE", None, "DUPLICATE_STAGE"]
    assert [e["state_after"] for e in body["events"]] == [
        "received",
        "received",
        "picked",
        "picked",
        "shipped",
        "shipped",
    ]
    # A duplicate of the final stage expects no further events.
    assert "no further events" in body["events"][5]["anomaly"]["expected"]


def test_regression_to_an_earlier_stage_is_an_anomaly():
    resp = audit(
        [
            ev("receive"),
            ev("pick"),
            ev("receive"),  # regression picked -> receive
            ev("ship"),
            ev("pick"),  # regression shipped -> pick
            ev("receive"),  # regression shipped -> receive
        ]
    )
    body = resp.json()
    codes = [e["anomaly"] and e["anomaly"]["error"] for e in body["events"]]
    assert codes == [
        None,
        None,
        "STAGE_REGRESSION",
        None,
        "STAGE_REGRESSION",
        "STAGE_REGRESSION",
    ]
    assert body["events"][2]["anomaly"]["found"] == "receive"
    assert body["events"][2]["anomaly"]["expected"] == "'ship'"
    assert body["summary"]["shipped"] == 1


def test_skipped_stage_is_an_anomaly():
    resp = audit([ev("receive"), ev("ship")])
    body = resp.json()
    anomaly = body["events"][1]["anomaly"]
    assert anomaly["error"] == "STAGE_SKIPPED"
    assert anomaly["expected"] == "'pick'"
    assert anomaly["found"] == "ship"
    assert "pick" in anomaly["message"]
    assert body["events"][1]["state_after"] == "received"


def test_summary_counts_each_final_state():
    resp = audit(
        [
            ev("receive", serial="S1"),
            ev("pick", serial="S1"),
            ev("ship", serial="S1"),  # S1 -> shipped
            ev("receive", serial="S2"),
            ev("pick", serial="S2"),  # S2 -> picked
            ev("receive", serial="S3"),  # S3 -> received
            ev("ship", serial="S4"),  # S4 -> none (anomaly)
        ]
    )
    assert resp.json()["summary"] == {
        "none": 1,
        "received": 1,
        "picked": 1,
        "shipped": 1,
    }


# ------------------------------------------------------------------ conflicts


def test_batch_conflict_reports_current_and_first_event_index():
    resp = audit(
        [
            ev("receive", batch="B1"),
            ev("pick", batch="B1"),
            ev("ship", batch="B2"),
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 2
    assert detail["first_index"] == 0
    assert detail["error"]["error"] == "CONFLICTING_BATCH"
    assert "B1" in detail["error"]["expected"]
    assert "B2" in detail["error"]["found"]
    assert set(detail) == {"event_index", "first_index", "error"}


def test_batch_absent_then_present_is_a_conflict():
    resp = audit([ev("receive", batch=None), ev("pick", batch="B1")])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"]["error"] == "CONFLICTING_BATCH"
    assert "no batch" in detail["error"]["expected"]


def test_expiry_conflict():
    resp = audit(
        [ev("receive", expiry="250131"), ev("pick", expiry="250228")]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 1
    assert detail["first_index"] == 0
    assert detail["error"]["error"] == "CONFLICTING_EXPIRY"
    assert "250131" in detail["error"]["expected"]
    assert "250228" in detail["error"]["found"]


def test_expiry_absent_then_present_is_a_conflict():
    resp = audit([ev("receive", expiry=None), ev("pick", expiry="250131")])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"]["error"] == "CONFLICTING_EXPIRY"
    assert "no expiry" in detail["error"]["expected"]


def test_day_00_and_explicit_last_day_are_a_raw_expiry_conflict():
    # 250200 and 250228 denote the same actual date but differ as scanned.
    resp = audit(
        [ev("receive", expiry="250200"), ev("pick", expiry="250228")]
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"]["error"] == "CONFLICTING_EXPIRY"


def test_conflict_is_checked_even_when_the_first_event_was_an_anomaly():
    resp = audit(
        [ev("pick", batch="B1"), ev("receive", batch="B2")]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 1
    assert detail["first_index"] == 0
    assert detail["error"]["error"] == "CONFLICTING_BATCH"


def test_consistent_attributes_across_events_pass():
    resp = audit(
        [
            ev("receive", batch="B1", expiry="250131"),
            ev("pick", batch="B1", expiry="250131"),
            ev("ship", batch="B1", expiry="250131"),
        ]
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["shipped"] == 1


# ---------------------------------------------------------------- scan errors


def test_missing_gtin_rejected():
    resp = audit([{"type": "receive", "scan": "1725013121SN1"}])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "MISSING_AI"
    assert "01" in detail["error"]["message"]


def test_missing_serial_rejected():
    resp = audit([{"type": "receive", "scan": f"01{GTIN_OK}17250131"}])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "MISSING_AI"
    assert "21" in detail["error"]["message"]


def test_duplicate_gtin_rejected():
    resp = audit(
        [{"type": "receive", "scan": f"01{GTIN_OK}01{GTIN2}1725013121SN1"}]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "DUPLICATE_AI"
    assert "01" in detail["error"]["message"]


def test_duplicate_serial_rejected():
    resp = audit(
        [{"type": "receive", "scan": f"01{GTIN_OK}1725013121A{GS}21B"}]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "DUPLICATE_AI"
    assert "21" in detail["error"]["message"]


def test_duplicate_batch_rejected():
    resp = audit(
        [
            {
                "type": "receive",
                "scan": f"01{GTIN_OK}1725013110A{GS}10B{GS}21SN1",
            }
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "DUPLICATE_AI"
    assert "10" in detail["error"]["message"]


def test_duplicate_expiry_rejected():
    resp = audit(
        [{"type": "receive", "scan": f"01{GTIN_OK}172501311725022821SN1"}]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 0
    assert detail["error"]["error"] == "DUPLICATE_AI"
    assert "17" in detail["error"]["message"]


def test_parser_error_reports_event_index_and_original_error():
    resp = audit(
        [
            ev("receive", serial="S1"),
            {"type": "receive", "scan": "01095011015300041725013121SN2"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["event_index"] == 1
    assert detail["error"]["error"] == "INVALID_CHECK_DIGIT"
    assert detail["error"]["offset"] == 15
    assert set(detail) == {"event_index", "error"}


def test_error_index_follows_event_position():
    resp = audit(
        [
            ev("receive", serial="S1"),
            ev("receive", serial="S2"),
            {"type": "receive", "scan": "not-a-gs1-string"},
        ]
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["event_index"] == 2


# ---------------------------------------------------- request model validation


def test_unknown_event_type_is_422():
    resp = audit([{"type": "return", "scan": scan()}])
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["loc"] == ["body", "events", 0, "type"]


def test_missing_events_field_is_422():
    resp = client.post("/trace-audit", json={})
    assert resp.status_code == 422


def test_missing_type_is_422():
    resp = client.post("/trace-audit", json={"events": [{"scan": scan()}]})
    assert resp.status_code == 422


def test_missing_scan_is_422():
    resp = client.post("/trace-audit", json={"events": [{"type": "receive"}]})
    assert resp.status_code == 422


def test_non_string_scan_is_422():
    resp = client.post(
        "/trace-audit", json={"events": [{"type": "receive", "scan": 123}]}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["loc"] == ["body", "events", 0, "scan"]


def test_events_not_a_list_is_422():
    resp = client.post("/trace-audit", json={"events": {"type": "receive"}})
    assert resp.status_code == 422
