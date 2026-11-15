#!/usr/bin/env python3
"""Synchronous, verified publishing to Nostr relays.

python-nostr's RelayManager hands events to background threads and never
reads the relay's OK reply, so a slow handshake or a rejection is silent.
This module opens one plain websocket per relay, sends the event, and waits
for the relay's ["OK", id, accepted, message] so every outcome is logged.
Handles NIP-42 AUTH challenges when a private key is supplied.
"""
import json
import ssl
import time
import websocket
from nostr.event import AuthMessage

logger = None


def _publish_one(url, event, privkey, timeout):
    ws = websocket.create_connection(url, timeout=timeout, sslopt={"cert_reqs": ssl.CERT_NONE})
    try:
        ws.send(event.to_message())
        deadline = time.time() + timeout
        authed = False
        challenge = None
        while time.time() < deadline:
            msg = json.loads(ws.recv())
            kind = msg[0] if msg else None
            if kind == "OK" and len(msg) >= 3 and msg[1] == event.id:
                reason = msg[3] if len(msg) > 3 else ""
                if msg[2]:
                    return True, reason or "accepted"
                # NIP-42: relay wants auth; answer once then resend
                if reason.startswith("auth-required") and privkey is not None and challenge and not authed:
                    am = AuthMessage(challenge=challenge, relay_url=url)
                    privkey.sign_event(am)
                    ws.send(am.to_message())
                    authed = True
                    ws.send(event.to_message())
                    continue
                return False, reason or "rejected"
            if kind == "AUTH" and len(msg) > 1:
                challenge = msg[1]
                continue
            if kind == "NOTICE":
                logger.debug(f"  {url} NOTICE: {msg[1] if len(msg) > 1 else ''}")
                continue
        return False, "no OK within timeout"
    finally:
        try:
            ws.close()
        except Exception:
            pass


def publishEvent(event, relays, privkey=None, timeout=10):
    """Publish a signed event to every write-enabled relay. Returns the
    number of relays that accepted it. Logs one line per relay."""
    accepted = 0
    for r in relays:
        url = r["url"] if isinstance(r, dict) else r
        if isinstance(r, dict) and not r.get("write", True):
            continue
        try:
            ok, reason = _publish_one(url, event, privkey, timeout)
        except Exception as e:
            ok, reason = False, f"{type(e).__name__}: {e}"
        if ok:
            accepted += 1
            logger.info(f"  {url}: accepted")
        else:
            logger.warning(f"  {url}: FAILED ({reason})")
    if accepted == 0:
        logger.warning(f"Event {event.id[:8]} was not accepted by any relay")
    return accepted
