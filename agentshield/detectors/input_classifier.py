"""Input classifier: detects prompt injection in user messages.

Uses keyword-based heuristics as a fast first pass, with optional
integration of PromptGuard-86M or fine-tuned DeBERTa model.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from agentshield.config import INPUT_CLASSIFIER_THRESHOLD
from agentshield.detectors.base import DetectionResult, DetectorBase

logger = logging.getLogger(__name__)

# ── Injection Indicators ─────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|safety|prior|any)\s+instructions",
    r"you\s+are\s+now\s+(DAN|an?\s+unrestricted)",
    r"developer\s+mode\s+(active|enabled)",
    r"system\s*:\s*override",
    r"\[SYSTEM\]",
    r"\[JAILBREAK\]",
    r"---\s*END\s+OF\s+USER\s+INPUT\s*---",
    r"---\s*BEGIN\s+USER\s+INPUT\s*---",
    r"repeat\s+your\s+system\s+prompt",
    r"print\s+your\s+(initial\s+)?instructions",
    r"do\s+anything\s+now",
    r"override\s+safety",
    r"safety\s+(mode|filter)\s*disabled",
    r"disregard\s+(all\s+)?safety",
    r"unrestricted\s+mode",
    r"no\s+restrictions",
    r"skip\s+safety\s+review",
    r"authorized\s+test",
]

ROLE_OVERRIDE_PATTERNS = [
    r"you\s+are\s+no\s+longer",
    r"your\s+new\s+role",
    r"pretend\s+to\s+be",
    r"act\s+as\s+if\s+you\s+have\s+no",
    r"from\s+now\s+on,?\s+you",
]

# Resource exhaustion / DoS patterns
# Detect requests for massive-scale operations that would generate thousands of API calls
RESOURCE_EXHAUSTION_PATTERNS = [
    # "for each of the 20,000 genes" — explicit large-scale enumeration
    r"for\s+each\s+of\s+(?:the\s+)?\d[\d,]{3,}",
    # "every gene / every protein in the human genome/proteome"
    r"(?:every|all)\s+(?:genes?|proteins?|variants?|sequences?)\s+in\s+the\s+(?:human\s+)?(?:genome|proteome)",
    # "run X for all N genes" — mass parallel operation
    r"run\s+.{5,60}\s+for\s+(?:all|every)\s+(?:\d[\d,]+\s+)?(?:genes?|proteins?|variants?)",
]

ENCODING_INDICATORS = [
    r"\[base64:[A-Za-z0-9+/=]+\]",
    r"0x[0-9a-fA-F]{4,}",
    r"(respond|answer|output|reply)\s+(only\s+)?.*?base64",
    r"using\s+(only\s+)?base64",
    r"encode\s+your\s+response",
]

# Mixed-script indicators (homoglyph attacks)
HOMOGLYPH_INDICATORS = [
    r"[\u0400-\u04ff]",  # Cyrillic chars embedded in Latin text
    r"[\u0370-\u03ff]",  # Greek chars in unexpected context
]

# Leetspeak indicators (3+ digit substitutions distinguishes from gene names like E2F1)
LEETSPEAK_INDICATORS = [
    r"[a-z]*[0-9][a-z]+[0-9][a-z]+[0-9]",  # e.g. "v1rul3nc3", "3nh4nc3" (not E2F1, CDK2)
]


class InputClassifier(DetectorBase):
    """Detect prompt injection attacks in user input.

    Operates in two modes:
      1. Pattern-based (default): Fast regex matching against known injection patterns.
      2. Model-based (optional): Uses PromptGuard-86M or fine-tuned model.
    """

    name = "input_classifier"

    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = INPUT_CLASSIFIER_THRESHOLD,
    ):
        self.threshold = threshold
        self.model = None
        self.tokenizer = None

        if model_path:
            self._load_model(model_path)

    def _load_model(self, model_path: str) -> None:
        """Load a transformer model for injection detection."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
            self.model.eval()
            logger.info("Loaded input classifier model from %s", model_path)
        except Exception as e:
            logger.warning("Failed to load model, using pattern-based detection: %s", e)

    def detect(
        self,
        user_input: Optional[str] = None,
        agent_output: Optional[str] = None,
        conversation_history: Optional[list[dict]] = None,
        tool_calls: Optional[list[dict]] = None,
    ) -> DetectionResult:
        """Detect prompt injection in user input."""
        if not user_input:
            return DetectionResult(
                detector_name=self.name,
                flagged=False,
                confidence=1.0,
                reason="No user input to analyze",
            )

        # Pattern-based detection
        pattern_score, matched_patterns = self._pattern_score(user_input)

        # Model-based detection (if available)
        model_score = 0.0
        if self.model is not None:
            model_score = self._model_score(user_input)

        # Combined score
        if self.model is not None:
            final_score = 0.4 * pattern_score + 0.6 * model_score
        else:
            final_score = pattern_score

        flagged = final_score >= self.threshold

        return DetectionResult(
            detector_name=self.name,
            flagged=flagged,
            confidence=final_score,
            risk_score=final_score,
            reason=f"Injection patterns: {matched_patterns}" if flagged else "No injection detected",
            metadata={"matched_patterns": matched_patterns, "model_score": model_score},
        )

    def _pattern_score(self, text: str) -> tuple[float, list[str]]:
        """Score text against injection patterns."""
        text_lower = text.lower()
        matched = []

        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text_lower):
                matched.append(pattern)

        for pattern in ROLE_OVERRIDE_PATTERNS:
            if re.search(pattern, text_lower):
                matched.append(f"role_override: {pattern}")

        for pattern in ENCODING_INDICATORS:
            if re.search(pattern, text_lower):
                matched.append(f"encoding: {pattern}")

        for pattern in RESOURCE_EXHAUSTION_PATTERNS:
            if re.search(pattern, text_lower):
                matched.append(f"resource_exhaustion: {pattern}")

        for pattern in HOMOGLYPH_INDICATORS:
            if re.search(pattern, text):  # Case-sensitive for Unicode
                matched.append(f"homoglyph: {pattern}")

        for pattern in LEETSPEAK_INDICATORS:
            if re.search(pattern, text_lower):
                matched.append(f"leetspeak: {pattern}")

        if not matched:
            return 0.0, []

        # Scale: 1 pattern = 0.5, 2 = 0.7, 3+ = 0.9+
        score = min(0.3 + 0.2 * len(matched), 1.0)
        return score, matched

    def _model_score(self, text: str) -> float:
        """Score text using the transformer model."""
        import torch

        inputs = self.tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)
            # Assume label 1 = injection
            return float(probs[0, 1].item())
