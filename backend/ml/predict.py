import os
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple
from backend.config import get_config

# Cache model in memory
_CACHED_MODEL = None

def get_loaded_model():
    """Safely retrieves or loads the trained ML pipeline."""
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    config = get_config()
    model_path = Path(config.ML_MODEL_PATH)
    if model_path.exists():
        try:
            _CACHED_MODEL = joblib.load(model_path)
            return _CACHED_MODEL
        except Exception as e:
            print(f"[!] Warning: Failed to deserialize ML model: {e}")
            return None
    return None

def predict_message(text: str) -> Dict[str, Any]:
    """
    Predicts whether a text is phishing or legitimate using the trained ML model.
    If the trained model file is not present, uses a documented transparent rule-based fallback.
    Does NOT fabricate ML predictions or evaluation metrics.
    """
    model = get_loaded_model()

    if model is not None:
        try:
            # Predict probabilities
            probs = model.predict_proba([text])[0]
            # probs[0] = Benign, probs[1] = Phishing
            phishing_prob = float(probs[1])
            predicted_label = int(model.predict([text])[0])
            confidence = float(max(probs))

            return {
                "prediction": predicted_label,
                "phishing_probability": round(phishing_prob, 4),
                "confidence": round(confidence, 4),
                "is_fallback": False,
                "model_type": type(model.named_steps.get('clf')).__name__
            }
        except Exception as e:
            print(f"[!] Error during ML model inference: {e}")

    # Documented transparent fallback when ML model binary is not yet trained
    from backend.services.text_analyzer import analyze_text_indicators
    indicators, flags = analyze_text_indicators(text)

    score_signals = (
        flags.get('urgency_count', 0) * 0.25 +
        flags.get('credential_count', 0) * 0.35 +
        flags.get('financial_count', 0) * 0.25 +
        flags.get('prize_count', 0) * 0.35 +
        (0.20 if flags.get('extracted_urls') else 0.0)
    )
    fallback_prob = min(0.95, score_signals)
    predicted_label = 1 if fallback_prob >= 0.50 else 0

    return {
        "prediction": predicted_label,
        "phishing_probability": round(fallback_prob, 4),
        "confidence": round(max(fallback_prob, 1 - fallback_prob), 4),
        "is_fallback": True,
        "model_type": "Transparent Rule-Based Fallback (Model Binary Unloaded)"
    }
