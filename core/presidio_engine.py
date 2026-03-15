 
#Presidio PII Detection Engine

#Custom recognizers: PK_CNIC, API_KEY, INTERNAL_ID

#Context-aware boosting and confidence calibration.

import time
from typing import List

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .config import (
    ENABLED_ENTITIES,
    PII_CONFIDENCE_THRESHOLDS,
    DEFAULT_PII_CONFIDENCE,
    CONTEXT_BOOST,
    ANONYMIZATION_OPERATORS,
)


# recognizer 1: Pakistani CNIC 
pk_cnic_recognizer = PatternRecognizer(
    supported_entity="PK_CNIC",
    name="PK CNIC Recognizer",
    patterns=[Pattern(name="pk_cnic_pattern", regex=r"\b\d{5}-\d{7}-\d{1}\b", score=0.85)],
    context=["cnic", "national id", "identity card", "nadra", "pakistani id"],
    supported_language="en",
)

# recognizer 2: API Keys 
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    name="API Key Recognizer",
    patterns=[
        Pattern(name="openai_key", regex=r"\bsk-[A-Za-z0-9]{20,}\b", score=0.9),
        Pattern(name="aws_access_key", regex=r"\bAKIA[0-9A-Z]{16,20}\b", score=0.9),
        Pattern(name="generic_api_key", regex=r"\b[A-Za-z0-9]{32,64}\b", score=0.4),
    ],
    context=["api key", "api_key", "secret", "token", "authorization", "bearer", "key"],
    supported_language="en",
)

#recognizer 3: Internal IDs  
internal_id_recognizer = PatternRecognizer(
    supported_entity="INTERNAL_ID",
    name="Internal ID Recognizer",
    patterns=[
        Pattern(name="employee_id", regex=r"\bEMP-\d{6,10}\b", score=0.85),
        Pattern(name="project_id", regex=r"\bPROJ-[A-Z0-9]{4,10}\b", score=0.85),
        Pattern(name="department_id", regex=r"\bDEPT-[A-Z]+-\d{3,6}\b", score=0.85),
    ],
    context=["employee", "project", "department", "internal", "id", "staff"],
    supported_language="en",
)


def _build_analyzer() -> AnalyzerEngine:
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        })
        nlp_engine = provider.create_engine()
    except OSError:
        print("[WARNING] en_core_web_lg not found, trying en_core_web_sm...")
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()
        except OSError:
            print("[ERROR] No spaCy model found. Run: python -m spacy download en_core_web_lg")
            raise

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    analyzer.registry.add_recognizer(pk_cnic_recognizer)
    analyzer.registry.add_recognizer(api_key_recognizer)
    analyzer.registry.add_recognizer(internal_id_recognizer)
    return analyzer


_analyzer: AnalyzerEngine = None
_anonymizer: AnonymizerEngine = None


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = _build_analyzer()
    return _analyzer


def get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


def _apply_context_boost(results: List[RecognizerResult], text: str) -> List[RecognizerResult]:
    context_map = {
        "PK_CNIC": ["cnic", "national id", "identity", "nadra"],
        "API_KEY": ["api", "key", "secret", "token", "bearer"],
        "INTERNAL_ID": ["employee", "project", "department", "staff", "internal"],
        "PHONE_NUMBER": ["phone", "call", "mobile", "cell", "contact"],
        "EMAIL_ADDRESS": ["email", "mail", "send", "contact"],
        "CREDIT_CARD": ["card", "payment", "visa", "mastercard", "credit"],
    }
    lower_text = text.lower()
    boosted = []
    for r in results:
        entity_contexts = context_map.get(r.entity_type, [])
        start = max(0, r.start - 50)
        end = min(len(text), r.end + 50)
        window = lower_text[start:end]
        if any(ctx in window for ctx in entity_contexts):
            r.score = min(1.0, r.score + CONTEXT_BOOST)
        boosted.append(r)
    return boosted


def _calibrate_confidence(results: List[RecognizerResult]) -> List[RecognizerResult]:
    calibrated = []
    for r in results:
        threshold = PII_CONFIDENCE_THRESHOLDS.get(r.entity_type, DEFAULT_PII_CONFIDENCE)
        if r.score >= threshold:
            calibrated.append(r)
    return calibrated


class PresidioResult:
    def __init__(self, raw_results, filtered_results, anonymized_text, latency_ms):
        self.raw_results = raw_results
        self.filtered_results = filtered_results
        self.anonymized_text = anonymized_text
        self.latency_ms = latency_ms
        self.entities_found = [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": round(r.score, 3)}
            for r in filtered_results
        ]

    def to_dict(self) -> dict:
        return {
            "entities_found": self.entities_found,
            "anonymized_text": self.anonymized_text,
            "latency_ms": round(self.latency_ms, 2),
        }


def analyze_pii(text: str) -> PresidioResult:
    start = time.perf_counter()
    analyzer = get_analyzer()
    anonymizer = get_anonymizer()

    raw_results = analyzer.analyze(text=text, language="en", entities=ENABLED_ENTITIES)
    boosted = _apply_context_boost(raw_results, text)
    filtered = _calibrate_confidence(boosted)

    operators = {}
    for entity_type, op_type in ANONYMIZATION_OPERATORS.items():
        if op_type == "replace":
            operators[entity_type] = OperatorConfig("replace", {"new_value": f"<{entity_type}>"})
        elif op_type == "mask":
            operators[entity_type] = OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_end": False})
        elif op_type == "redact":
            operators[entity_type] = OperatorConfig("redact", {})
    operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "<REDACTED>"})

    anonymized = anonymizer.anonymize(text=text, analyzer_results=filtered, operators=operators)
    latency = (time.perf_counter() - start) * 1000
    return PresidioResult(raw_results, filtered, anonymized.text, latency)
