 
# gateway — shared functionsvy server, GUI,etc
 
import time
from .injection_detector import detect_injection
from .presidio_engine import analyze_pii
from .policy_engine import decide

def scan(text: str) -> dict:
    """Run the full security pipeline on input text."""
    total_start = time.perf_counter()

    injection_result = detect_injection(text)
    presidio_result = analyze_pii(text)
    policy_decision = decide(text, injection_result, presidio_result)

    total_latency = (time.perf_counter() - total_start) * 1000

    return {
        "input_length": len(text),
        "injection_analysis": injection_result.to_dict(),
        "pii_analysis": presidio_result.to_dict(),
        "policy_decision": policy_decision.to_dict(),
        "total_latency_ms": round(total_latency, 2),
    }
