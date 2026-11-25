"""Unit tests: PKCE, webhook test vector, SSE parser, DPoP proofs."""

from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt
import pytest

from moon_sso import DPoPKey, PKCE, SSEParser, WebhookVerificationError, WebhookVerifier, code_challenge, generate_code_verifier, sign_webhook
from moon_sso.contrib._web import is_htmx, safe_return_to
from moon_sso.pkce import b64url, random_token
from moon_sso.sse import ReconnectPolicy

# ---- PKCE ----


def test_pkce_rfc7636_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_generate() -> None:
    for _ in range(50):
        p = PKCE.generate()
        assert 43 <= len(p.verifier) <= 128
        assert set(p.verifier) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        assert p.challenge == b64url(hashlib.sha256(p.verifier.encode()).digest())
        assert p.method == "S256"
    assert len({generate_code_verifier() for _ in range(100)}) == 100


def test_pkce_rejects_bad_verifier() -> None:
    with pytest.raises(ValueError):
        code_challenge("short")
    with pytest.raises(ValueError):
        code_challenge("a" * 129)
    with pytest.raises(ValueError):
        random_token(8)


# ---- Standard Webhooks ----

VECTOR = {
    "secret": "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
    "id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
    "timestamp": 1614265330,
    "body": '{"test": 2432232314}',
    "signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
}


def _headers(sig: str, ts: int = VECTOR["timestamp"], msg_id: str = VECTOR["id"]) -> dict[str, str]:  # type: ignore[assignment]
    return {"webhook-id": msg_id, "webhook-timestamp": str(ts), "webhook-signature": sig}


def test_webhook_spec_vector_sign() -> None:
    assert sign_webhook(VECTOR["secret"], VECTOR["id"], VECTOR["timestamp"], VECTOR["body"]) == VECTOR["signature"]


def test_webhook_spec_vector_verify() -> None:
    v = WebhookVerifier(VECTOR["secret"])
    ev = v.verify(VECTOR["body"].encode(), _headers(VECTOR["signature"]), now=VECTOR["timestamp"] + 10)
    assert ev.webhook_id == VECTOR["id"]
    assert ev.raw == {"test": 2432232314}
    assert not ev.duplicate
    again = v.verify(VECTOR["body"].encode(), _headers(VECTOR["signature"]), now=VECTOR["timestamp"] + 10)
    assert again.duplicate


def test_webhook_multiple_signatures_and_case_insensitive_headers() -> None:
    v = WebhookVerifier(VECTOR["secret"], dedupe=False)
    sig = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= v2,whatever " + VECTOR["signature"]
    headers = {k.upper(): val for k, val in _headers(sig).items()}
    v.verify(VECTOR["body"], headers, now=VECTOR["timestamp"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b, h: (b + b" ", h),
        lambda b, h: (b, {**h, "webhook-id": "msg_other"}),
        lambda b, h: (b, {**h, "webhook-signature": "v1,AAAA"}),
        lambda b, h: (b, {**h, "webhook-signature": VECTOR["signature"].replace("v1,", "v0,")}),
        lambda b, h: (b, {k: v for k, v in h.items() if k != "webhook-timestamp"}),
    ],
)
def test_webhook_rejects_tampering(mutate) -> None:  # type: ignore[no-untyped-def]
    v = WebhookVerifier(VECTOR["secret"])
    body, headers = mutate(VECTOR["body"].encode(), _headers(VECTOR["signature"]))
    with pytest.raises(WebhookVerificationError):
        v.verify(body, headers, now=VECTOR["timestamp"])


def test_webhook_timestamp_tolerance() -> None:
    v = WebhookVerifier(VECTOR["secret"])
    with pytest.raises(WebhookVerificationError):
        v.verify(VECTOR["body"], _headers(VECTOR["signature"]), now=VECTOR["timestamp"] + 301)
    with pytest.raises(WebhookVerificationError):
        v.verify(VECTOR["body"], _headers(VECTOR["signature"]), now=VECTOR["timestamp"] - 301)
    v.verify(VECTOR["body"], _headers(VECTOR["signature"]), now=VECTOR["timestamp"] + 299)


def test_webhook_event_fields_and_staleness() -> None:
    secret = "whsec_" + base64.b64encode(b"k" * 32).decode()
    body = json.dumps({"id": "evt_7", "seq": 7, "type": "user.updated", "occurred_at": "2026-01-01T00:00:00Z",
                       "data": {"sub": "s1", "profile_version": 4, "changed": ["nickname"]}})
    now = int(time.time())
    sig = sign_webhook(secret, "evt_7", now, body)
    ev = WebhookVerifier(secret).verify(body, _headers(sig, now, "evt_7"))
    assert (ev.id, ev.seq, ev.type, ev.sub, ev.profile_version) == ("evt_7", 7, "user.updated", "s1", 4)
    assert ev.is_stale(4) and ev.is_stale(5) and not ev.is_stale(3) and not ev.is_stale(None)


# ---- SSE ----


def test_sse_parser_frames_comments_retry() -> None:
    p = SSEParser()
    stream = (
        "retry: 4200\n\n"
        ": ping\n\n"
        "id: 41\nevent: user.updated\ndata: {\"a\":1}\n\n"
        "data: line1\ndata: line2\n\n"
        "event: resync\ndata: {}\n\n"
    )
    events = p.feed(stream)
    assert [e.event for e in events] == ["user.updated", "message", "resync"]
    assert events[0].id == "41" and events[0].json() == {"a": 1}
    assert events[1].data == "line1\nline2" and events[1].id == "41"  # last id persists
    assert p.retry == 4200 and events[0].retry == 4200
    assert p.last_event_id == "41"


def test_sse_parser_split_chunks_and_line_endings() -> None:
    p = SSEParser()
    text = "id: 7\r\nevent: user.disabled\r\ndata: {\"x\":\r\n\r\nid: 8\revent: a\rdata: b\r\r"
    out = []
    for ch in text:  # one character at a time
        out.extend(p.feed(ch))
    assert [(e.id, e.event, e.data) for e in out] == [("7", "user.disabled", '{"x":'), ("8", "a", "b")]


def test_sse_parser_ignores_unknown_and_empty() -> None:
    p = SSEParser()
    assert p.feed("foo: bar\n\n\n\nid: 3\n\n") == []
    assert p.last_event_id == "3"
    assert p.feed("data\n\n")[0].data == ""
    assert p.feed("retry: abc\n\n") == [] and p.retry is None


def test_reconnect_policy() -> None:
    pol = ReconnectPolicy(jitter=0.5)
    for _ in range(20):
        d = pol.delay(None)
        assert 3.0 <= d <= 8.5
    assert 2.0 <= pol.delay(2000) <= 2.5
    pol.failure()
    pol.failure()
    assert 8.0 <= pol.delay(2000) <= 8.5
    pol.success()
    assert pol.delay(1000) <= 1.5


# ---- DPoP ----


def test_dpop_proof_structure() -> None:
    key = DPoPKey.generate()
    proof = key.proof("post", "https://sso.test/oauth/token?x=1#frag", nonce="n1")
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt" and header["alg"] == "ES256"
    assert set(header["jwk"]) == {"kty", "crv", "x", "y"}
    pub = jwt.PyJWK(header["jwk"]).key
    claims = jwt.decode(proof, pub, algorithms=["ES256"])
    assert claims["htm"] == "POST" and claims["htu"] == "https://sso.test/oauth/token"
    assert claims["nonce"] == "n1" and abs(claims["iat"] - time.time()) < 5 and len(claims["jti"]) >= 22
    assert key.proof("POST", "https://x/y") != key.proof("POST", "https://x/y")


def test_dpop_thumbprint_rfc7638_and_persistence() -> None:
    key = DPoPKey.generate()
    jwk = key.public_jwk
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"))
    assert key.thumbprint == b64url(hashlib.sha256(canon.encode()).digest())
    again = DPoPKey.from_pem(key.to_pem())
    assert again.thumbprint == key.thumbprint
    enc = DPoPKey.from_pem(key.to_pem(b"pw"), password=b"pw")
    assert enc.thumbprint == key.thumbprint
    key.update_nonce("abc")
    assert "nonce" in jwt.decode(key.proof("POST", "https://a/b"), options={"verify_signature": False})
    assert "jkt" in repr(key) and "PRIVATE" not in repr(key)


# ---- web helpers ----


def test_safe_return_to_and_htmx() -> None:
    assert safe_return_to("/a?b=1") == "/a?b=1"
    for bad in ("https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)", "", None, "/x\r\nSet-Cookie: a"):
        assert safe_return_to(bad, "/home") == "/home"
    assert is_htmx({"HX-Request": "true"}) and is_htmx({"hx-request": "TRUE"}) and not is_htmx({})
