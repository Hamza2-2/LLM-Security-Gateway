 
#Configuration for the Presidio-Based LLM Security Mini-Gateway.
 

# injection Detection 
INJECTION_KEYWORDS = {
    "high": [
        "ignore previous instructions",
        "ignore all instructions",
        "disregard your instructions",
        "forget your instructions",
        "override your programming",
        "you are now",
        "act as a",
        "pretend you are",
        "new persona",
        "jailbreak",
        "developer mode",
        "DAN mode",
        "ignore safety",
    ],
    "medium": [
        "system prompt",
        "reveal your prompt",
        "show me your instructions",
        "show your instructions",
        "show me your rules",
        "what are your rules",
        "what are your instructions",
        "repeat your system",
        "output your instructions",
        "tell me your system",
        "tell me your instructions",
        "display your instructions",
        "print your instructions",
        "what is your prompt",
        "base64",
        "encode this",
        "bypass",
        "without restrictions",
        "no limitations",
    ],
    "low": [
        "hypothetically",
        "in theory",
        "for research purposes",
        "educational purposes only",
        "role play",
        "simulate",
        "as an experiment",
    ],
}

INJECTION_SCORE_WEIGHTS = {
    "high": 3,
    "medium": 2,
    "low": 1,
}

INJECTION_BLOCK_THRESHOLD = 4
INJECTION_WARN_THRESHOLD = 2

# Presidio PII 
ENABLED_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PK_CNIC",
    "API_KEY",
    "INTERNAL_ID",
]

PII_CONFIDENCE_THRESHOLDS = {
    "PERSON": 0.6,
    "EMAIL_ADDRESS": 0.7,
    "PHONE_NUMBER": 0.5,
    "CREDIT_CARD": 0.7,
    "IBAN_CODE": 0.7,
    "IP_ADDRESS": 0.5,
    "PK_CNIC": 0.8,
    "API_KEY": 0.85,
    "INTERNAL_ID": 0.8,
}

DEFAULT_PII_CONFIDENCE = 0.5

# context-aware Scoring Boost 
CONTEXT_BOOST = 0.15

# policy Engine 
CRITICAL_PII_TYPES = ["API_KEY", "CREDIT_CARD", "PK_CNIC", "IBAN_CODE"]

# aonymization Operators 
ANONYMIZATION_OPERATORS = {
    "DEFAULT": "replace",
    "PHONE_NUMBER": "mask",
    "CREDIT_CARD": "mask",
    "EMAIL_ADDRESS": "replace",
    "API_KEY": "redact",
}

# LLM Backend  placeholder (future implementation)
LLM_MODEL = "lattepanda9000ultrapromaxgpt-9.67"
LLM_MAX_TOKENS = 512
