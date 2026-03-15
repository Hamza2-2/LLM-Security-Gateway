 
#Injection Detection Module
#detect prompt injection, jailbreak attempts thru keyword-based scoring.
 

import re
import time
from dataclasses import dataclass, field

from .config import (
    INJECTION_KEYWORDS,
    INJECTION_SCORE_WEIGHTS,
    INJECTION_BLOCK_THRESHOLD,
    INJECTION_WARN_THRESHOLD,
)


@dataclass
class InjectionResult:
    score: int = 0
    matched_patterns: list = field(default_factory=list)
    severity: str = "none"
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.score >= INJECTION_BLOCK_THRESHOLD

    @property
    def is_warned(self) -> bool:
        return self.score >= INJECTION_WARN_THRESHOLD

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "matched_patterns": self.matched_patterns,
            "severity": self.severity,
            "is_blocked": self.is_blocked,
            "is_warned": self.is_warned,
            "latency_ms": round(self.latency_ms, 2),
        }


def detect_injection(user_input: str) -> InjectionResult:
    start = time.perf_counter()
    result = InjectionResult()
    normalized = user_input.lower().strip()

    for severity, patterns in INJECTION_KEYWORDS.items():
        weight = INJECTION_SCORE_WEIGHTS[severity]
        for pattern in patterns:
            if pattern.lower() in normalized:
                result.score += weight
                result.matched_patterns.append(
                    {"pattern": pattern, "severity": severity, "weight": weight}
                )

    special_ratio = len(re.findall(r'[^\w\s]', user_input)) / max(len(user_input), 1)
    if special_ratio > 0.35:
        result.score += 2
        result.matched_patterns.append(
            {"pattern": "high_special_char_ratio", "severity": "medium", "weight": 2}
        )

    if len(user_input) > 5000:
        result.score += 1
        result.matched_patterns.append(
            {"pattern": "excessive_length", "severity": "low", "weight": 1}
        )

    if result.score >= INJECTION_BLOCK_THRESHOLD:
        result.severity = "high"
    elif result.score >= INJECTION_WARN_THRESHOLD:
        result.severity = "medium"
    elif result.score > 0:
        result.severity = "low"

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result
