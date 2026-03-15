 
# Policy Engine — Allow / Mask / Block  
 

import time
from dataclasses import dataclass

from .config import (
    INJECTION_BLOCK_THRESHOLD,
    INJECTION_WARN_THRESHOLD,
    CRITICAL_PII_TYPES,
)


@dataclass
class PolicyDecision:
    action: str
    reason: str
    injection_score: int
    pii_count: int
    critical_pii: list
    output_text: str
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "injection_score": self.injection_score,
            "pii_count": self.pii_count,
            "critical_pii": self.critical_pii,
            "output_text": self.output_text[:200] + "..." if len(self.output_text) > 200 else self.output_text,
            "latency_ms": round(self.latency_ms, 2),
        }


def decide(original_text, injection_result, presidio_result) -> PolicyDecision:
    start = time.perf_counter()

    score = injection_result.score
    entities = presidio_result.entities_found
    pii_count = len(entities)
    critical = [e for e in entities if e["entity_type"] in CRITICAL_PII_TYPES]

    if score >= INJECTION_BLOCK_THRESHOLD:
        return PolicyDecision(action="BLOCK", reason=f"Injection score {score} exceeds block threshold ({INJECTION_BLOCK_THRESHOLD})", injection_score=score, pii_count=pii_count, critical_pii=[c["entity_type"] for c in critical], output_text="[BLOCKED] Request rejected due to potential prompt injection.", latency_ms=(time.perf_counter() - start) * 1000)

    if score >= INJECTION_WARN_THRESHOLD and pii_count > 0:
        return PolicyDecision(action="BLOCK", reason=f"Injection score {score} with {pii_count} PII entities detected", injection_score=score, pii_count=pii_count, critical_pii=[c["entity_type"] for c in critical], output_text="[BLOCKED] Suspicious input containing sensitive data.", latency_ms=(time.perf_counter() - start) * 1000)

    if pii_count > 0:
        pii_types = list(set(e["entity_type"] for e in entities))
        return PolicyDecision(action="MASK", reason=f"PII detected: {', '.join(pii_types)}", injection_score=score, pii_count=pii_count, critical_pii=[c["entity_type"] for c in critical], output_text=presidio_result.anonymized_text, latency_ms=(time.perf_counter() - start) * 1000)

    return PolicyDecision(action="ALLOW", reason="No threats detected", injection_score=score, pii_count=0, critical_pii=[], output_text=original_text, latency_ms=(time.perf_counter() - start) * 1000)
