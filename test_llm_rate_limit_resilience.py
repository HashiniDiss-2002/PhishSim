"""
test_llm_rate_limit_resilience.py
------------------------------------
Verifies the fix for a real failure hit while running evaluation campaigns:
generate_pretext() calling Groq once per employee, back-to-back, tripped
Groq's free-tier per-minute rate limit ("429 Too Many Requests"), and the
old retry logic (3 attempts, fixed 2s/4s waits) wasn't patient enough —
the whole campaign aborted and rolled back, losing every employee's
already-generated pretext (see admin.py: create_campaign()'s
db.rollback() on an unhandled exception).

Two independent changes are covered here:
  1. services/pretext_generator.py's _call_llm(): more retry attempts,
     exponential backoff, and respecting a server-sent Retry-After header
     when Groq provides one.
  2. admin.py's create_campaign(): a configurable pacing delay
     (PRETEXT_DELAY_SECONDS) between employees' LLM calls, so the limit
     is less likely to be hit in the first place — the same pattern
     already used for email sending (SEND_DELAY_SECONDS).

This file unit-tests _call_llm() directly with a mocked requests.post, so
it needs no Flask app, database, or network access — same offline,
deterministic style as every other test_*.py here.
"""

import os
import sys

# Make sure a real network call is never attempted even if this somehow
# runs with a real key in the environment.
os.environ.pop("GROQ_API_KEY", None)

import services.pretext_generator as pretext_generator


class _FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def json(self):
        return self._json_data

    @property
    def text(self):
        return str(self._json_data)

    def raise_for_status(self):
        import requests
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} error", response=self
            )


def _success_response():
    return _FakeResponse(
        200,
        {"choices": [{"message": {"content": '{"subject": "s", "html_body": "b", '
                                              '"persuasion_principle": "authority"}'}}]},
    )


def test_retries_past_429_then_succeeds(monkeypatch):
    """Two 429s followed by a 200 should succeed without raising, using
    exactly 3 calls — proving the retry loop actually retries rather than
    giving up after the first failure."""
    calls = {"count": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["count"] += 1
        if calls["count"] <= 2:
            return _FakeResponse(429, headers={})
        return _success_response()

    monkeypatch.setattr(pretext_generator.requests, "post", fake_post)
    monkeypatch.setattr(pretext_generator.time, "sleep", lambda s: None)  # don't actually wait in tests

    result = pretext_generator._call_llm("irrelevant prompt")
    assert result["subject"] == "s"
    assert calls["count"] == 3
    print("[PASS] _call_llm retries past two 429s and succeeds on the third attempt")


def test_respects_retry_after_header(monkeypatch):
    """When Groq sends a Retry-After header, that value is used for the
    wait instead of the default exponential backoff."""
    calls = {"count": 0}
    sleep_calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            return _FakeResponse(429, headers={"Retry-After": "7"})
        return _success_response()

    def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr(pretext_generator.requests, "post", fake_post)
    monkeypatch.setattr(pretext_generator.time, "sleep", fake_sleep)

    pretext_generator._call_llm("irrelevant prompt")
    assert sleep_calls[0] == 7.0, f"Expected Retry-After's 7s to be used, got {sleep_calls}"
    print("[PASS] A Retry-After header value is honoured instead of the default backoff")


def test_gives_up_after_max_retries(monkeypatch):
    """Sustained 429s (the limit never clears) should eventually raise,
    using the configured LLM_MAX_RETRIES attempts — not hang forever."""
    calls = {"count": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["count"] += 1
        return _FakeResponse(429, headers={})

    monkeypatch.setattr(pretext_generator.requests, "post", fake_post)
    monkeypatch.setattr(pretext_generator.time, "sleep", lambda s: None)

    import requests
    try:
        pretext_generator._call_llm("irrelevant prompt")
        raised = False
    except requests.exceptions.HTTPError:
        raised = True

    assert raised, "A sustained 429 should eventually raise, not loop forever"
    assert calls["count"] == pretext_generator.LLM_MAX_RETRIES
    print(f"[PASS] Gives up after {pretext_generator.LLM_MAX_RETRIES} attempts on a sustained 429")


if __name__ == "__main__":
    # Lightweight monkeypatch stand-in so this file can be run directly
    # with `python test_llm_rate_limit_resilience.py`, matching every
    # other test_*.py in this project, without requiring pytest.
    class _MonkeyPatch:
        def __init__(self):
            self._originals = []

        def setattr(self, obj, name, value):
            self._originals.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, value in reversed(self._originals):
                setattr(obj, name, value)

    for test_fn in (test_retries_past_429_then_succeeds,
                    test_respects_retry_after_header,
                    test_gives_up_after_max_retries):
        mp = _MonkeyPatch()
        try:
            test_fn(mp)
        finally:
            mp.undo()

    print("\nAll LLM rate-limit resilience checks passed.")
