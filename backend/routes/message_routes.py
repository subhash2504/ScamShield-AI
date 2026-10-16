"""
PhishGuard AI - Message & Email Analysis Routes
Handles SMS/WhatsApp/Chat text and Email inspection endpoints.
"""
from flask import Blueprint, request, jsonify, current_app
from backend.services.text_analyzer import analyze_text_indicators, normalize_text, extract_urls
from backend.services.risk_scorer import calculate_risk
from backend.ml.predict import predict_message
from backend.database.db import record_scan

message_bp = Blueprint('message', __name__)


@message_bp.route('/analyze/message', methods=['POST'])
def analyze_message():
    """
    Analyze a suspicious SMS, WhatsApp, or chat message for phishing indicators.
    Expects JSON: { "message": "<text>", "channel": "message" (optional) }
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid request. JSON body with "message" key required.'}), 400

    raw_message = data.get('message', '').strip()
    channel = data.get('channel', 'message')

    if not raw_message:
        return jsonify({'error': 'Message text cannot be empty.'}), 400

    if len(raw_message) > 8000:
        return jsonify({'error': 'Message exceeds maximum allowed length of 8000 characters.'}), 400

    # Step 1: Normalize & Extract Text Features
    normalized = normalize_text(raw_message)

    # Step 2: Heuristic Text Analysis
    indicators, flags = analyze_text_indicators(normalized)

    # Step 3: ML Classifier Inference
    ml_result = predict_message(normalized)

    # Step 4: Composite Risk Scoring
    risk = calculate_risk(
        input_type=channel,
        indicators=indicators,
        ml_result=ml_result,
        features=flags,
        raw_input=normalized
    )

    # Step 5: Record scan telemetry (no full content retained)
    try:
        record_scan(
            scan_type=channel,
            risk_category=risk['risk_category'],
            risk_score=risk['risk_score'],
            indicators=risk['indicators'],
            recommendations=risk.get('recommendations', []),
            target_snippet=normalized[:80],
            db_path=current_app.config.get('DATABASE_PATH')
        )
    except Exception as e:
        current_app.logger.warning(f'Scan record failed (non-critical): {e}')

    # Step 6: Build Response Payload
    return jsonify({
        'risk_score': risk['risk_score'],
        'risk_category': risk['risk_category'],
        'summary': risk['summary'],
        'indicators': risk['indicators'],
        'recommendations': risk.get('recommendations', []),
        'extracted_urls': flags.get('extracted_urls', []),
        'model_confidence': risk.get('model_confidence'),
        'decision_notes': risk.get('decision_notes', ''),
        'model_type': ml_result.get('model_type', 'Rule-Based Fallback'),
        'is_fallback': ml_result.get('is_fallback', True),
        'channel': channel
    }), 200


@message_bp.route('/analyze/email', methods=['POST'])
def analyze_email():
    """
    Analyze an email for BEC, phishing, or social engineering threats.
    Expects JSON: { "sender": "...", "subject": "...", "body": "..." }
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid request. JSON body required.'}), 400

    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('body', '').strip()

    if not subject or not body:
        return jsonify({'error': 'Both "subject" and "body" are required fields.'}), 400

    if len(body) > 12000:
        return jsonify({'error': 'Email body exceeds maximum allowed length of 12000 characters.'}), 400

    # Combine sender, subject, and body into unified analysis corpus
    combined_text = f"From: {sender}\nSubject: {subject}\n\n{body}" if sender else f"Subject: {subject}\n\n{body}"
    normalized = normalize_text(combined_text)

    # Heuristic Analysis
    indicators, flags = analyze_text_indicators(normalized)

    # Additional Email-Specific: Sender domain mismatch detection
    if sender:
        _check_sender_anomalies(sender, indicators)

    # ML Inference
    ml_result = predict_message(normalized)

    # Risk Scoring
    risk = calculate_risk(
        input_type='email',
        indicators=indicators,
        ml_result=ml_result,
        features=flags,
        raw_input=normalized
    )

    # Record scan
    try:
        snippet = f"[{subject[:40]}] {body[:40]}"
        record_scan(
            scan_type='email',
            risk_category=risk['risk_category'],
            risk_score=risk['risk_score'],
            indicators=risk['indicators'],
            recommendations=risk.get('recommendations', []),
            target_snippet=snippet,
            db_path=current_app.config.get('DATABASE_PATH')
        )
    except Exception as e:
        current_app.logger.warning(f'Email scan record failed (non-critical): {e}')

    return jsonify({
        'risk_score': risk['risk_score'],
        'risk_category': risk['risk_category'],
        'summary': risk['summary'],
        'indicators': risk['indicators'],
        'recommendations': risk.get('recommendations', []),
        'extracted_urls': flags.get('extracted_urls', []),
        'model_confidence': risk.get('model_confidence'),
        'decision_notes': risk.get('decision_notes', ''),
        'model_type': ml_result.get('model_type', 'Rule-Based Fallback'),
        'is_fallback': ml_result.get('is_fallback', True),
        'channel': 'email'
    }), 200


def _check_sender_anomalies(sender: str, indicators: list):
    """
    Detects suspicious sender patterns common in Business Email Compromise (BEC).
    Mutates the indicators list directly.
    """
    import re

    sender_lower = sender.lower()

    # Free webmail used for executive impersonation
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
    authority_titles = ['ceo', 'chief', 'director', 'president', 'executive', 'vp ', 'vice president', 'cfo', 'coo']

    is_executive_label = any(title in sender_lower for title in authority_titles)
    uses_free_provider = any(p in sender_lower for p in free_providers)

    if is_executive_label and uses_free_provider:
        indicators.append({
            'title': 'Executive Impersonation via Free Email Provider (BEC Red Flag)',
            'severity': 'high',
            'description': (
                f"The sender display name suggests executive authority ({sender[:60]}), "
                "but uses a free consumer email provider. Legitimate corporate executives "
                "use company domain email accounts. This is a hallmark of Business Email Compromise (BEC)."
            )
        })

    # Generic lookalike domains (hyphens, freemail-branded)
    domain_match = re.search(r'@([\w.\-]+)', sender_lower)
    if domain_match:
        domain = domain_match.group(1)
        if domain.count('-') >= 2 or re.search(r'\b(mail|secure|corp|office|support)\b', domain):
            indicators.append({
                'title': 'Suspicious Sender Domain Structure',
                'severity': 'medium',
                'description': (
                    f"Sender domain '{domain}' contains suspicious formatting typical of "
                    "disposable or impersonation email domains used in phishing campaigns."
                )
            })
