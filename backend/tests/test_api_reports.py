"""API end-to-end: create → poll → triage → every report format."""
import time

from fastapi.testclient import TestClient

from app.main import app
from app.reports.exports import FORMATS
from conftest import SAMPLES

client = TestClient(app)


def wait(audit_id: str, timeout: float = 120) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = client.get(f"/api/audits/{audit_id}/status").json()
        if s["status"] not in ("queued", "running"):
            return s
        time.sleep(0.3)
    raise AssertionError("audit did not finish")


def create(name: str) -> dict:
    import json
    payload = {"project": name, "source": {"kind": "path", "location": str(SAMPLES / name)},
               "options": {"use_llm": False, "external_tools": []}}
    r = client.post("/api/audits", data={"payload": json.dumps(payload)})
    assert r.status_code == 200, r.text
    return r.json()


def test_health_rules_settings():
    assert client.get("/api/health").json()["ok"]
    assert len(client.get("/api/rules").json()) > 60
    s = client.get("/api/settings").json()
    assert "llm" in s and s["llm"]["api_key"] == ""


def test_full_flow_and_triage():
    a = create("vulnerable-ts-mcp")
    s = wait(a["id"])
    assert s["status"] == "done" and s["decision"] == "NO_GO"
    full = client.get(f"/api/audits/{a['id']}").json()
    crit = [f for f in full["findings"] if f["severity"] == "critical" and f["status"] == "open"]
    # a justification is mandatory
    r = client.patch(f"/api/audits/{a['id']}/findings/{crit[0]['fingerprint']}", json={"status": "accepted", "reason": "", "by": "t", "remember": False})
    assert r.status_code == 400
    for f in crit:
        r = client.patch(f"/api/audits/{a['id']}/findings/{f['fingerprint']}",
                         json={"status": "accepted", "reason": "Compensating control documented", "by": "tester", "remember": False})
        assert r.status_code == 200
    after = client.get(f"/api/audits/{a['id']}/status").json()
    assert after["readiness"] > s["readiness"], "accepting every critical must lift the critical gate"
    for fmt, (mime, _ext) in FORMATS.items():
        r = client.get(f"/api/audits/{a['id']}/report/{fmt}")
        assert r.status_code == 200 and len(r.content) > 1000, fmt
        assert r.headers["content-type"].split(";")[0] == mime.split(";")[0]


def test_triage_is_remembered_for_next_audit():
    a = create("hardened-python-mcp")
    wait(a["id"])
    full = client.get(f"/api/audits/{a['id']}").json()
    f = next(x for x in full["findings"] if x["status"] == "open")
    client.patch(f"/api/audits/{a['id']}/findings/{f['fingerprint']}",
                 json={"status": "false_positive", "reason": "Gateway validates Origin", "by": "sec-team", "remember": True})
    b = client.post(f"/api/audits/{a['id']}/rerun").json()
    wait(b["id"])
    nxt = client.get(f"/api/audits/{b['id']}").json()
    g = next(x for x in nxt["findings"] if x["fingerprint"] == f["fingerprint"])
    assert g["status"] == "false_positive" and "carried over" in g["status_reason"]
    assert nxt["comparison"] is not None


def test_bad_inputs():
    import json
    r = client.post("/api/audits", data={"payload": json.dumps({"source": {"kind": "path", "location": "/definitely/missing"}})})
    assert r.status_code == 400
    r = client.post("/api/audits", data={"payload": json.dumps({"source": {"kind": "git", "location": "file:///etc"}})})
    assert r.status_code == 400
    assert client.get("/api/audits/nope").status_code == 404
    assert client.get("/api/unknown").status_code == 404
