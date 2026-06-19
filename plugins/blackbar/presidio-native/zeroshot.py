"""
Layer 2 — local zero-shot classifier for GDPR Art. 9 special categories in free
text (paraphrase, not just explicit terms). Optional and OFF by default: enable
with BLACKBAR_ENABLE_ZEROSHOT=1 after installing requirements-zeroshot.txt.

It wraps a multilingual NLI model as a Presidio EntityRecognizer. For each
sentence it runs zero-shot multi-label classification against the Art. 9 label
set and emits a span for the whole sentence when a label clears the threshold.
Everything runs locally — no text leaves the machine.

Trade-offs (documented honestly):
  * sentence-level spans, not exact phrases -> coarser anonymization
  * slower than regex (tens of ms .. seconds per sentence on CPU)
  * best-effort: false positives/negatives are expected; keep a human in the loop
  * heavy deps (transformers + torch)

Config:
  BLACKBAR_ZEROSHOT_MODEL      default MoritzLaurer/mDeBERTa-v3-base-mnli-xnli
  BLACKBAR_ZEROSHOT_THRESHOLD  default 0.85
"""
import os
import re

from presidio_analyzer import EntityRecognizer, RecognizerResult

# candidate label -> blackbar entity type
LABELS = {
    "health or medical information": "HEALTH_CONDITION",
    "religious belief": "RELIGIOUS_BELIEF",
    "political opinion": "POLITICAL_OPINION",
    "racial or ethnic origin": "ETHNIC_ORIGIN",
    "sexual orientation or sex life": "SEXUAL_ORIENTATION",
    "trade union membership": "TRADE_UNION",
}

_SENT_SPLIT = re.compile(r"[^.!?\n]+(?:[.!?]+|\n|$)")


def _sentences(text):
    """Yield (start, end, sentence) preserving character offsets."""
    for m in _SENT_SPLIT.finditer(text):
        s = m.group()
        if s.strip():
            yield m.start(), m.end(), s


class ZeroShotRecognizer(EntityRecognizer):
    def __init__(self, supported_language="en", threshold=None, model=None):
        super().__init__(
            supported_entities=sorted(set(LABELS.values())),
            supported_language=supported_language,
            name="ZeroShotArt9",
        )
        self.threshold = float(threshold if threshold is not None
                               else os.environ.get("BLACKBAR_ZEROSHOT_THRESHOLD", "0.85"))
        self.model = model or os.environ.get(
            "BLACKBAR_ZEROSHOT_MODEL", "MoritzLaurer/mDeBERTa-v3-base-mnli-xnli")
        self._pipe = None

    def load(self):
        pass

    def _pipeline(self):
        if self._pipe is None:
            import torch
            from transformers import pipeline  # lazy: only when actually used
            # Force CPU + fp32: some checkpoints ship fp16 weights that crash on
            # CPU ("mat1 and mat2 must have the same dtype, Float vs Half").
            self._pipe = pipeline(
                "zero-shot-classification", model=self.model,
                device=-1, torch_dtype=torch.float32,
            )
        return self._pipe

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        pipe = self._pipeline()
        candidate = list(LABELS.keys())
        for start, end, sent in _sentences(text):
            if len(sent.strip()) < 8:
                continue
            out = pipe(sent, candidate_labels=candidate, multi_label=True)
            for label, score in zip(out["labels"], out["scores"]):
                if score < self.threshold:
                    continue
                ent = LABELS[label]
                if entities and ent not in entities:
                    continue
                results.append(RecognizerResult(
                    entity_type=ent, start=start, end=end, score=float(score)))
        return results
