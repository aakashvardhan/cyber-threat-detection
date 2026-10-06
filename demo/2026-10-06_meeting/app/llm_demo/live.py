"""Live Gemma 4 call. The API key is a function argument only: never stored, logged or echoed."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from app.config import GEMMA_BASE_URL, GEMMA_MODEL

class LiveCallError(RuntimeError):
    """Raised with a message that is safe to show (the key has been scrubbed)."""


def scrub(text: str, api_key: str) -> str:
    text = str(text)
    return text.replace(api_key, "[redacted]") if api_key else text


def ask_gemma(prompt: str, api_key: str, system: str, model: str = GEMMA_MODEL, base_url: str = GEMMA_BASE_URL) -> str:
    if not api_key:
        raise LiveCallError("No API key provided.")
    body = {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
    headers = {"Content-Type": "application/json", "User-Agent": "gemma-demo/1.0",
               "Authorization": f"Bearer {api_key}"}
    last = ""
    for attempt in range(4):
        req = urllib.request.Request(f"{base_url}/chat/completions", json.dumps(body).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                return json.load(resp)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            detail = scrub(e.read().decode(errors="replace")[:300], api_key)
            last = f"HTTP {e.code}: {detail}"
            if e.code in (401, 403) or (e.code == 400 and "api key" in detail.lower()):
                raise LiveCallError(f"The API key was rejected (HTTP {e.code}). Check the key and try again.") from None
            if e.code not in (429, 500, 502, 503) or attempt == 3:
                raise LiveCallError(last) from None
            time.sleep(float(e.headers.get("Retry-After") or 2 ** attempt))
        except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as e:
            raise LiveCallError(scrub(f"Request failed: {e}", api_key)) from None
    raise LiveCallError(last)
