"""CAPE Pillar A+ — AI-assisted narration for explainability & remediation.

Scope, deliberately: this module ONLY narrates facts that CAPE's
deterministic engines already computed — the rule trace in
`OpportunityTrace` and the countermeasure catalog in `RemediationPlan`.
It never generates attack steps, exploitation guidance, or anything
`cape attack`/`cape plan` would use; those stay fully deterministic.

Two reasons for that split, not one:
  1. Google's Gemini models apply safety guardrails to offensive-security
     content, so attack-narrative output would be unreliable at best and
     refused at worst — the wrong tool for the job.
  2. Explainability and remediation narration only ever rephrases and
     contextualizes numbers CAPE already derived and validated
     (`trace.score_consistent`), so there's nothing for the model to get
     wrong that changes the actual finding — it can't invent a different
     severity or score, only explain the one that's already there.

Fails soft everywhere: no API key, no network, or an SDK error all fall
back to "AI narration unavailable" rather than breaking `cape explain`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from typing import Iterator, Optional

from cape.core.config import get_config
from cape.show.explain.trace_models import OpportunityTrace

logger = logging.getLogger(__name__)

_SYSTEM_INSTRUCTION = """You are a narration layer inside CAPE, an automated pentesting tool.
You will be given a JSON "trace" that a deterministic rule engine already
produced: which conditions matched, the exact score formula and its
components, supporting evidence, and a prioritized remediation plan.

Your job is ONLY to explain this trace in plain language for a security
operator. Rules:
- Never change, second-guess, or restate a different score or severity
  than the one given. Treat final_score/final_severity as ground truth.
- Never suggest exploitation steps, attack commands, or payloads. If asked
  implicitly by the data to describe "what an attacker could do", stay at
  the level of impact/outcome (e.g. "an attacker could read arbitrary
  files"), not method or tooling.
- Ground every sentence in a field from the trace JSON. Do not invent
  facts, CVEs, or details not present in the input.
- Be concise: a short paragraph on why this matters (grounded in the
  score components and evidence), then a second paragraph that walks the
  operator through the remediation plan in plain language — what to do
  immediately vs. short-term vs. long-term, calling out effort level and
  any MITRE mitigation ID, and closing with how to verify the fix using
  the given verification_steps. Never propose a countermeasure that
  isn't already in the remediation plan. Plain text, no markdown headers.
"""


def _get_api_key() -> Optional[str]:
    """Resolve the Gemini API key.

    Checks the SDK's own conventional env vars first, then CAPE's config
    (which itself reads CAPE_GOOGLE_AI_API_KEY or ~/.cape/config.yaml).
    """
    return (
        os.environ.get("GOOGLE_AI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or get_config().google_ai_api_key
    )


def ai_narration_available() -> bool:
    """Whether AI narration can run at all (key configured, feature on)."""
    cfg = get_config()
    return bool(cfg.ai_narration_enabled and _get_api_key())


def _trace_hash(trace: OpportunityTrace) -> str:
    """Hash the scoring-relevant parts of a trace, for cache invalidation.

    If the underlying score components, conditions, or remediation plan
    change (e.g. after a re-scan or a knowledge-base update), this hash
    changes too, so a stale cached narrative is never served.
    """
    payload = {
        "score": trace.final_score,
        "severity": trace.final_severity,
        "conditions": [c.model_dump(mode="json") for c in trace.conditions],
        "components": [c.model_dump(mode="json") for c in trace.score_components],
        "remediation": trace.remediation.to_dict() if trace.remediation else None,
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _build_prompt(trace: OpportunityTrace, redact_target: bool) -> str:
    """Serialize a trace to the JSON payload sent to the model.

    `redact_target` swaps the real target identifier for a placeholder,
    for engagements where the operator doesn't want the target
    IP/hostname leaving the machine even for narration.
    """
    data = json.loads(trace.model_dump_json())
    if redact_target:
        data["target"] = "TARGET-REDACTED"
        for f in data.get("supporting_findings", []):
            f.pop("raw_output_file", None)
    return json.dumps(data, indent=2)


def _cache_get(opportunity_id: str, trace_hash: str, model: str) -> Optional[str]:
    from cape.db.session import db_session
    from cape.db.models import AINarrativeCache

    try:
        with db_session() as session:
            row = (
                session.query(AINarrativeCache)
                .filter(
                    AINarrativeCache.opportunity_id == opportunity_id,
                    AINarrativeCache.trace_hash == trace_hash,
                    AINarrativeCache.model == model,
                )
                .order_by(AINarrativeCache.created_at.desc())
                .first()
            )
            return row.narrative if row else None
    except Exception as e:
        logger.warning(f"AI narrative cache lookup failed: {e}")
        return None


def _cache_put(opportunity_id: str, trace_hash: str, model: str, narrative: str) -> None:
    from cape.db.session import db_session
    from cape.db.models import AINarrativeCache

    try:
        with db_session() as session:
            session.add(
                AINarrativeCache(
                    id=str(uuid.uuid4()),
                    opportunity_id=opportunity_id,
                    trace_hash=trace_hash,
                    model=model,
                    narrative=narrative,
                )
            )
            session.commit()
    except Exception as e:
        logger.warning(f"AI narrative cache write failed: {e}")


def narrate(
    trace: OpportunityTrace,
    redact_target: bool = False,
    use_cache: bool = True,
) -> str:
    """Return a plain-language narrative for one OpportunityTrace.

    Never raises: on any failure (no key, network error, SDK error) this
    returns a short explanatory string instead, so `cape explain --ai`
    degrades gracefully to "AI narration unavailable" rather than
    crashing the whole command.
    """
    cfg = get_config()
    if not cfg.ai_narration_enabled:
        return "AI narration is disabled (ai_narration_enabled: false in config)."

    api_key = _get_api_key()
    if not api_key:
        return (
            "AI narration unavailable: no API key configured. Set GOOGLE_AI_API_KEY "
            "(or GEMINI_API_KEY) in your environment, or CAPE_GOOGLE_AI_API_KEY."
        )

    opp_id = str(trace.opportunity_id)
    thash = _trace_hash(trace)

    if use_cache:
        cached = _cache_get(opp_id, thash, cfg.ai_model)
        if cached:
            return cached

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return "AI narration unavailable: 'google-genai' is not installed (pip install google-genai)."

    try:
        client = genai.Client(api_key=api_key)
        prompt = _build_prompt(trace, redact_target=redact_target)
        response = client.models.generate_content(
            model=cfg.ai_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_INSTRUCTION,
                temperature=0.2,
                max_output_tokens=512,
            ),
        )
        narrative = (response.text or "").strip()
        if not narrative:
            return "AI narration unavailable: the model returned an empty response."
    except Exception as e:
        logger.warning(f"AI narration call failed: {e}")
        return f"AI narration unavailable: {e}"

    if use_cache:
        _cache_put(opp_id, thash, cfg.ai_model, narrative)

    return narrative


def narrate_stream(
    trace: OpportunityTrace,
    redact_target: bool = False,
) -> Iterator[str]:
    """Stream a narrative chunk-by-chunk, for a live-typing CLI effect.

    Bypasses the cache (streaming is for the interactive/demo case); use
    `narrate()` for the cached, non-streaming path. Yields a single
    explanatory chunk and returns if narration can't run at all.
    """
    cfg = get_config()
    api_key = _get_api_key()
    if not cfg.ai_narration_enabled or not api_key:
        yield narrate(trace, redact_target=redact_target)
        return

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        yield "AI narration unavailable: 'google-genai' is not installed (pip install google-genai)."
        return

    try:
        client = genai.Client(api_key=api_key)
        prompt = _build_prompt(trace, redact_target=redact_target)
        stream = client.models.generate_content_stream(
            model=cfg.ai_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_INSTRUCTION,
                temperature=0.2,
                max_output_tokens=512,
            ),
        )
        for chunk in stream:
            if chunk.text:
                yield chunk.text
    except Exception as e:
        logger.warning(f"AI narration stream failed: {e}")
        yield f"\n[AI narration interrupted: {e}]"
