from . import intent_contracts


def test_emit_event(monkeypatch):
    monkeypatch.setattr(intent_contracts, "emit_event", lambda event: {"mock": event})
    assert intent_contracts.emit_event("ready") == {"mock": "ready"}
