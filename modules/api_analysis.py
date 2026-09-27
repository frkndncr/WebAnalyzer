"""Pure, dependency-free helpers for the API security scanner.

Response-type detection and the XSS "safe context" check, extracted from
api_security_scanner.py so they can be unit tested without HTTP or the scanner
object. ``BugBountyScanner`` delegates to these.
"""
import json


def is_json_response(text: str) -> bool:
    """True when ``text`` is a JSON object/array body."""
    if not text or len(text) < 2:
        return False
    text = text.strip()
    if text and text[0] in ("{", "[") and text[-1] in ("}", "]"):
        try:
            json.loads(text)
            return True
        except Exception:
            pass
    return False


def is_xml_response(text: str) -> bool:
    """True when ``text`` looks like an XML body."""
    if not text or len(text) < 10:
        return False
    text = text.strip()
    return text.startswith("<?xml") or (text.startswith("<") and text.endswith(">"))


def is_payload_safe_context(content: str, payload: str) -> bool:
    """True when an XSS ``payload`` only appears in a safe context in ``content``.

    Safe means: not present at all, inside an HTML comment, or HTML/URL-encoded.
    A False result means the raw payload is reflected and potentially executable.
    """
    payload_pos = content.find(payload)
    if payload_pos == -1:
        return True  # not reflected

    # Inside an HTML comment?
    comment_start = content.rfind("<!--", 0, payload_pos)
    comment_end = content.find("-->", payload_pos)
    if comment_start != -1 and comment_end != -1:
        return True

    # Reflected only in an encoded form? An "encoded" variant that is identical
    # to the raw payload (e.g. a payload with no quotes) proves nothing — the
    # raw payload was already found above, so treating it as encoded would hide
    # a real reflected XSS. Only genuinely different encodings count as safe.
    encoded_versions = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("<", "%3C").replace(">", "%3E"),
        payload.replace('"', "&quot;").replace("'", "&#x27;"),
    ]
    for encoded in encoded_versions:
        if encoded != payload and encoded in content:
            return True

    return False
