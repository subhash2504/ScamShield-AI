from typing import List, Dict, Any, Optional

def calculate_risk(
    input_type: str,
    indicators: List[Dict[str, Any]],
    ml_result: Optional[Dict[str, Any]] = None,
    features: Optional[Dict[str, Any]] = None,
    raw_input: str = ""
) -> Dict[str, Any]:
    """
    Documented Risk Scoring & Explainability Engine:
    - Calculates a heuristic risk index (0-100)
    - Blends model probability with deterministic security rules
    - Provides categorical classification (High Risk, Medium Risk, Low Risk, Unable to Determine)
    - Documents decision rationale and contradictory evidence
    - Formulates prioritized actionable recommendations
    """
    features = features or {}
    clean_input = (raw_input or "").strip()

    # 1. Edge Case: Insufficient Content
    if len(clean_input) < 6 and input_type != 'url':
        return {
            "risk_score": 50.0,
            "risk_category": "Unable to Determine",
            "summary": "Evidence is insufficient. The provided message or text snippet is too brief to extract meaningful linguistic cues or threat features.",
            "indicators": indicators,
            "recommendations": [
                "Provide the complete message or email context including sender information for a reliable security assessment.",
                "Never share sensitive passwords or verification codes if you are uncertain of the sender."
            ],
            "model_confidence": None,
            "decision_notes": "Input length < 6 characters; returned Unable to Determine."
        }

    # 2. Compute Rule-Based Heuristic Subscore (0 to 100)
    high_count = sum(1 for ind in indicators if ind.get('severity') == 'high')
    med_count = sum(1 for ind in indicators if ind.get('severity') == 'medium')
    low_count = sum(1 for ind in indicators if ind.get('severity') == 'low')

    # Heuristic weighting:
    # High severity indicator: 28 pts each
    # Medium severity: 15 pts each
    # Low severity: 5 pts each
    raw_rule_score = (high_count * 28.0) + (med_count * 15.0) + (low_count * 5.0)
    rule_score = min(100.0, max(5.0 if indicators else 0.0, raw_rule_score))

    # 3. Model Blending and Contradiction Handling
    decision_notes = []
    final_score = rule_score
    model_conf = None

    if ml_result and not ml_result.get('is_fallback', False):
        phishing_prob = ml_result.get('phishing_probability', 0.5)
        model_conf = ml_result.get('confidence', 0.5)
        ml_score = phishing_prob * 100.0

        # Weighted Ensemble: 55% Heuristic Rules + 45% ML Classifier
        blended = (0.55 * rule_score) + (0.45 * ml_score)

        # Check for Contradictory Evidence:
        if high_count >= 2 and phishing_prob < 0.35:
            # High-threat rules present, but ML had low score
            final_score = max(75.0, blended)
            decision_notes.append("Documented rule override: Critical indicators (e.g. credential harvesting or deceptive URLs) detected despite low ML n-gram score.")
        elif high_count == 0 and med_count == 0 and phishing_prob > 0.80:
            # ML flagged high probability due to generic vocab, but no specific attack patterns
            final_score = min(60.0, blended)
            decision_notes.append("Documented calibration: ML flagged high probability, but absence of hard credential or urgency cues capped rating at Medium Risk.")
        else:
            final_score = blended
            decision_notes.append("Score synthesized from balanced combination of ML classifier inference and security heuristic rules.")
    elif ml_result and ml_result.get('is_fallback', True):
        decision_notes.append("ML model binary unloaded; score calculated via transparent deterministic security rules.")
        final_score = rule_score
    else:
        decision_notes.append("URL static structure analysis performed using domain and syntax heuristics.")
        final_score = rule_score

    final_score = round(min(100.0, max(0.0, final_score)), 1)

    # 4. Risk Categorization
    if final_score >= 70.0:
        risk_category = "High Risk"
        summary = "High probability of phishing or scam activity. Strong social engineering triggers, credential solicitation, or deceptive domain patterns were detected."
    elif final_score >= 40.0:
        risk_category = "Medium Risk"
        summary = "Moderate risk indicators observed. While not definitively malicious, this message contains suspicious elements that warrant heightened caution."
    else:
        risk_category = "Low Risk"
        summary = "Low immediate threat signatures detected. Note: Absence of known indicators does not guarantee absolute safety; always exercise prudent security vigilance."

    # 5. Tailored Safety Recommendations
    recommendations = []
    has_credentials = any('Credential' in ind.get('title', '') for ind in indicators)
    has_urgency = any('Urgency' in ind.get('title', '') for ind in indicators)
    has_wire = any('Payment' in ind.get('title', '') or 'Wire' in ind.get('title', '') for ind in indicators)
    has_prize = any('Prize' in ind.get('title', '') for ind in indicators)
    has_url = any('Link' in ind.get('title', '') or 'URL' in ind.get('title', '') for ind in indicators) or input_type == 'url'

    if has_credentials:
        recommendations.append("Do NOT enter any passwords, PINs, or verification codes on linked pages.")
        recommendations.append("If you have already submitted credentials, reset your password immediately and activate Multi-Factor Authentication (MFA).")
    if has_wire:
        recommendations.append("Verify any requested funds transfer out-of-band using an independently sourced, known-good phone number.")
        recommendations.append("Do NOT purchase gift cards or send cryptocurrency under time pressure.")
    if has_prize:
        recommendations.append("Do not pay processing fees to claim unexpected prizes; legitimate lotteries do not ask for advance payment.")
    if has_url:
        recommendations.append("Do NOT click directly on links in unverified messages; navigate directly to official websites by typing the known URL in your browser.")
        recommendations.append("Inspect the actual registered domain hierarchy rather than trusting display names.")
    if has_urgency:
        recommendations.append("Take time to verify the request independently; scammers rely on artificial panic to circumvent rational judgment.")

    if not recommendations:
        recommendations.append("Verify the sender's identity through official channels if this communication was unexpected.")
        recommendations.append("Keep your device operating system and browser security updates current.")

    return {
        "risk_score": final_score,
        "risk_category": risk_category,
        "summary": summary,
        "indicators": indicators,
        "recommendations": recommendations,
        "model_confidence": model_conf,
        "decision_notes": " ".join(decision_notes)
    }
