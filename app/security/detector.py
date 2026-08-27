"""
Halyx — Multi-Layer Detection Engine
Combines four independent layers, each catching what the others might miss:
  1. Regex        — exact known attack phrasing (fast, zero cost)
  2. Fuzzy match  — reworded/typo'd versions of known phrases
  3. Semantic     — meaning-based similarity, catches full paraphrases
  4. LLM judge    — optional deep check, only runs on ambiguous cases
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.models.schemas import ThreatType
from app.security.fuzzy import fuzzy_detect
from app.security.semantic import semantic_detect
from app.security.llm_judge import llm_judge

_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (all |any )?(previous|prior|above) (instructions|rules)",
    r"forget (your|all|previous) instructions",
    r"you are now",
    r"new instructions?:",
    r"system prompt",
    r"act as (if|though)",
    r"override (your|the) (rules|instructions|policy)",
]

_EXFILTRATION_PATTERNS = [
    r"send (this|it|the file|secret|password|credentials?)",
    r"email (this|it|to) ",
    r"upload (this|it) to",
    r"post (this|it) to",
    r"share (this|it) with",
]

_COMPILED_OVERRIDE = [re.compile(p, re.IGNORECASE) for p in _INSTRUCTION_OVERRIDE_PATTERNS]
_COMPILED_EXFIL = [re.compile(p, re.IGNORECASE) for p in _EXFILTRATION_PATTERNS]


@dataclass
class DetectionResult:
    threat_type: ThreatType
    matched_patterns: List[str] = field(default_factory=list)
    injection_score: int = 0
    layers_triggered: List[str] = field(default_factory=list)


def _regex_detect(content: str):
    override_hits = [p.pattern for p in _COMPILED_OVERRIDE if p.search(content)]
    exfil_hits = [p.pattern for p in _COMPILED_EXFIL if p.search(content)]
    return override_hits, exfil_hits


def detect(content: str, tool: Optional[str] = None, arguments: Optional[Dict] = None) -> DetectionResult:
    arguments = arguments or {}
    matched: List[str] = []
    layers: List[str] = []
    score = 0

    # Layer 1: Regex
    override_hits, exfil_hits = _regex_detect(content)
    if override_hits or exfil_hits:
        matched.extend([f"regex:'{p}'" for p in override_hits + exfil_hits])
        layers.append("regex")
        score += 90 if (override_hits and exfil_hits) else (60 if override_hits else 50)

    # Layer 2: Fuzzy
    fuzzy_matches, fuzzy_score = fuzzy_detect(content)
    if fuzzy_matches:
        matched.extend(fuzzy_matches)
        layers.append("fuzzy")
        score = max(score, fuzzy_score)

    # Layer 3: Semantic
    semantic_matches, semantic_score = semantic_detect(content)
    if semantic_matches:
        matched.extend(semantic_matches)
        layers.append("semantic")
        score = max(score, semantic_score)

    # Layer 4: LLM judge — only spend the API call on ambiguous cases (some
    # signal already, but not already a slam-dunk regex block)
    if 20 <= score < 80:
        is_injection, llm_score, note = llm_judge(content, tool, arguments)
        if is_injection is True:
            matched.append(f"llm:{note}")
            layers.append("llm")
            score = max(score, llm_score, 70)  # LLM confirming pushes it high
        elif is_injection is False:
            matched.append(f"llm:{note}")
            layers.append("llm")
            # LLM disagrees — don't erase other layers' evidence, just don't add to it

    if not matched:
        return DetectionResult(threat_type=ThreatType.NONE, matched_patterns=[], injection_score=0, layers_triggered=[])

    if override_hits and exfil_hits:
        threat_type = ThreatType.INDIRECT_PROMPT_INJECTION
    elif override_hits or "llm" in layers or fuzzy_matches or semantic_matches:
        threat_type = ThreatType.SUSPICIOUS_INSTRUCTION_OVERRIDE
    else:
        threat_type = ThreatType.SENSITIVE_DATA_EXFILTRATION

    return DetectionResult(
        threat_type=threat_type,
        matched_patterns=matched,
        injection_score=min(score, 100),
        layers_triggered=layers,
    )