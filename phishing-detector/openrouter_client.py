"""
API Integration Module - talks to the OpenRouter API.

The AI is used as a second opinion on top of the rule-based detector.
If no API key is configured, or the request fails, the caller still gets
a usable result from the rule engine alone.
"""

import json
import os
import re

import requests

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
TIMEOUT = 25

SYSTEM_PROMPT = (
    "You are a phishing URL analyst. You are given a URL and the features "
    "extracted from it. Decide whether the URL is safe, suspicious, or phishing. "
    "Judge only from the URL text and features; you cannot open the page. "
    "Reply with JSON only, no markdown fences, using exactly this shape: "
    '{"verdict": "safe|suspicious|phishing", "confidence": 0-100, '
    '"reasons": ["short reason", "..."], "explanation": "two sentences for a non-technical user"}'
)


class OpenRouterError(Exception):
    pass


def is_configured() -> bool:
    return bool(os.environ.get("OPENROUTER_API_KEY"))


def _parse_json(text: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            raise OpenRouterError("The model did not return valid JSON")
        return json.loads(match.group(0))


def analyse(url: str, features: dict) -> dict:
    """Ask the model for a verdict. Raises OpenRouterError on failure."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise OpenRouterError("OPENROUTER_API_KEY is not set")

    slim = {k: v for k, v in features.items() if k != "host"}
    payload = {
        "model": DEFAULT_MODEL,
        "max_tokens": 600,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"URL: {url}\nExtracted features: {json.dumps(slim, default=str)}",
            },
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": os.environ.get("APP_URL", "http://localhost:5000"),
        "X-Title": "Phishing Website Detection System",
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise OpenRouterError(f"Network error: {exc}") from exc

    if response.status_code != 200:
        raise OpenRouterError(f"API error {response.status_code}: {response.text[:200]}")

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise OpenRouterError("The API response was in an unexpected format") from exc

    data = _parse_json(content)
    verdict = str(data.get("verdict", "")).lower()
    if verdict not in ("safe", "suspicious", "phishing"):
        verdict = "suspicious"

    try:
        confidence = int(float(data.get("confidence", 50)))
    except (TypeError, ValueError):
        confidence = 50

    reasons = data.get("reasons") or []
    if isinstance(reasons, str):
        reasons = [reasons]

    return {
        "verdict": verdict,
        "confidence": max(0, min(confidence, 100)),
        "reasons": [str(r) for r in reasons][:5],
        "explanation": str(data.get("explanation", "")).strip(),
        "model": DEFAULT_MODEL,
    }