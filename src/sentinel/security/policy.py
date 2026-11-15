
import re


# Explicit malicious requests made directly by the user.
DIRECT_ATTACK_PATTERNS = [
    r"\bignore\s+(all\s+)?(previous|prior)\s+instructions\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b",
    r"\b(?:expose|reveal|disclose|print)\b.*\b(?:internal|system|hidden)\s+instructions\b",
    r"\breveal\s+(your\s+|the\s+)?(internal\s+)?system\s+prompt\b",
    r"\bexport\s+all\s+customer\b",
    r"\bcustomer\s+email\s+addresses\b",
    r"\bbypass\s+(your\s+)?security\b",
    r"\bignore\s+your\s+security\s+rules\b",
    r"\breveal\s+restricted\s+internal\s+data\b",
    r"\bappend\s+the\s+hidden\s+assistant\s+configuration\b",
    r"\bretrieve\s+private\s+customer\s+details\b",
    r"\bconfidential\s+account\s+register\b",
    r"\brestricted\s+supplier\s+agreements\b",
    r"\bprivate\s+employee\s+records\b",
    r"\bhidden\s+operational\s+instructions\b",
]


# Known prompt-injection markers.
# Generic words such as "important:" are deliberately excluded
# to avoid classifying legitimate factual content as malicious.
UNTRUSTED_INSTRUCTION_MARKERS = [
    "system override:",
    "ignore the user",
    "export all customer records",
    "send all confidential",
    "reveal the system prompt",
]


# Contextual patterns for instruction-like content in retrieved documents.
# These deliberately combine an action with a sensitive target.
INSTRUCTION_PATTERNS = [
    # Attempts to override instructions.
    r"\bignore\b.*\b(user|instructions|task|security rules)\b",
    r"\bdisregard\b.*\b(user|instructions|task|security rules)\b",
    r"\bsystem\s+override\b",

    # Attempts to disclose internal information.
    r"\b(reveal|disclose|print|expose)\b.*\b(system prompt|operational prompt|internal data|internal instructions|assistant configuration)\b",
    r"\b(hidden|private|internal)\s+(assistant\s+)?(configuration|instructions|prompt)\b",

    # Attempts to access or export sensitive records.
    r"\b(export|extract|retrieve|access|obtain)\b.*\b(customer records|customer details|customer data|employee records|financial documents|account register)\b",
    r"\b(private|confidential|restricted)\b.*\b(customer|employee|account|financial|supplier)\b",

    # Attempts to disclose confidential contracts or documents.
    r"\b(send|forward|share|transmit)\b.*\b(confidential|restricted|private|internal)\b",
    r"\b(include|append|attach)\b.*\b(confidential|restricted|private|internal|hidden)\b",

    # Attempts to use privileged access.
    r"\buse\s+your\s+privileged\s+access\b",
    r"\bprivileged\s+access\b.*\b(retrieve|access|export|disclose)\b",

    # Attempts to replace the requested answer with restricted information.
    r"\breplace\b.*\b(hidden|private|internal)\s+(operational\s+)?(instructions|data|prompt|configuration)\b",
    r"\bignore\b.*\b(original\s+question|original\s+request|user'?s?\s+question)\b",
    r"\b(expose|reveal|disclose)\b.*\b(internal|confidential|restricted)\s+(operational\s+)?(data|information|instructions)\b",
    r"\breplace\b.*\b(confidential|restricted|private|internal)\b",

    r"\boverride\b.*\b(previous|prior|system|security)\s+instructions\b",
    r"\b(extract|export|retrieve|access|obtain)\b.*\bcustomer emails?\b",
]


def is_direct_attack(user_query: str) -> bool:
    """
    Detect known direct malicious requests in the user query.

    This is a rule-based detector, not a general semantic classifier.
    """
    if not isinstance(user_query, str):
        return False

    text = user_query.lower()

    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in DIRECT_ATTACK_PATTERNS
    )


def is_instruction_like(sentence: str) -> bool:
    """
    Identify known instruction-like patterns in untrusted text.

    This is a heuristic classifier. It cannot guarantee detection
    of novel or obfuscated prompt injections.
    """
    if not isinstance(sentence, str):
        return False

    text = sentence.strip()

    if not text:
        return False

    lower_text = text.lower()

    # Explicit known markers.
    if any(
        marker in lower_text
        for marker in UNTRUSTED_INSTRUCTION_MARKERS
    ):
        return True

    # Contextual instruction patterns.
    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in INSTRUCTION_PATTERNS
    )


def split_sentences(document: str) -> list[str]:
    """
    Split a document into sentences using basic punctuation rules.

    This simple splitter may not handle every abbreviation,
    URL, or complex document format correctly.
    """
    if not isinstance(document, str):
        return []

    return [
        sentence.strip()
        for sentence in re.split(
            r"(?<=[.!?])\s+",
            document.strip()
        )
        if sentence.strip()
    ]


def sanitize_retrieved_document(document: str) -> str:
    """
    Retain sentences that do not match known instruction patterns.

    Retrieved documents are treated as untrusted data.
    Matching sentences are removed before answer construction.

    Important:
    This is a deterministic heuristic, not a complete
    prompt-injection defence.
    """
    sentences = split_sentences(document)

    retained_sentences = [
        sentence
        for sentence in sentences
        if not is_instruction_like(sentence)
    ]

    return " ".join(retained_sentences).strip()


def sanitize_documents(documents: list[str]) -> list[str]:
    """
    Sanitize a list of retrieved documents and discard empty results.
    """
    return [
        cleaned
        for document in documents
        if (
            cleaned := sanitize_retrieved_document(document)
        )
    ]
