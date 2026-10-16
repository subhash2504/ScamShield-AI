"""
PhishGuard AI - URL & Screenshot (OCR) Analysis Routes
Handles URL inspection and image OCR extraction endpoints.
"""
import os
import io
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from backend.services.url_analyzer import analyze_url_heuristics
from backend.services.risk_scorer import calculate_risk
from backend.database.db import record_scan

url_bp = Blueprint('url', __name__)


@url_bp.route('/analyze/url', methods=['POST'])
def analyze_url():
    """
    Perform static heuristic analysis on a suspicious URL without making network requests.
    Expects JSON: { "url": "<target url>" }
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid request. JSON body with "url" key required.'}), 400

    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'URL cannot be empty.'}), 400

    if len(raw_url) > 2000:
        return jsonify({'error': 'URL exceeds maximum allowed length of 2000 characters.'}), 400

    # Get threat intel key from config if available
    threat_intel_key = current_app.config.get('THREAT_INTEL_API_KEY', '')

    # Static URL Heuristic Analysis (zero network requests)
    indicators, features = analyze_url_heuristics(
        raw_url,
        threat_intel_key=threat_intel_key if threat_intel_key else None
    )

    # Risk Scoring (URL mode — no ML model for URL, heuristics only)
    risk = calculate_risk(
        input_type='url',
        indicators=indicators,
        ml_result=None,
        features=features,
        raw_input=raw_url
    )

    # Record scan telemetry
    try:
        record_scan(
            scan_type='url',
            risk_category=risk['risk_category'],
            risk_score=risk['risk_score'],
            indicators=risk['indicators'],
            recommendations=risk.get('recommendations', []),
            target_snippet=raw_url[:80],
            db_path=current_app.config.get('DATABASE_PATH')
        )
    except Exception as e:
        current_app.logger.warning(f'URL scan record failed (non-critical): {e}')

    return jsonify({
        'risk_score': risk['risk_score'],
        'risk_category': risk['risk_category'],
        'summary': risk['summary'],
        'indicators': risk['indicators'],
        'recommendations': risk.get('recommendations', []),
        'url_features': features,
        'model_confidence': None,
        'decision_notes': risk.get('decision_notes', ''),
        'analysis_type': 'Static Heuristic (Zero-Execution)',
        'channel': 'url'
    }), 200


@url_bp.route('/analyze/screenshot', methods=['POST'])
def analyze_screenshot():
    """
    Extract text from an uploaded screenshot using OCR and optionally analyze it.
    Accepts multipart/form-data with 'screenshot' file field.
    Optional: 'extract_only=true' to skip analysis and just return extracted text.
    """
    if 'screenshot' not in request.files:
        return jsonify({'error': 'No screenshot file uploaded. Use "screenshot" as the form field name.'}), 400

    uploaded_file = request.files['screenshot']

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({'error': 'Empty file upload received.'}), 400

    # Validate MIME type
    allowed_mime = current_app.config.get('ALLOWED_MIME_TYPES', {'image/png', 'image/jpeg'})
    if uploaded_file.mimetype not in allowed_mime:
        return jsonify({
            'error': f'Unsupported file type: {uploaded_file.mimetype}. Only PNG and JPEG images are accepted.'
        }), 415

    # Read file into memory buffer (never written to disk for safety)
    try:
        file_bytes = uploaded_file.read()
        if len(file_bytes) > current_app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024):
            return jsonify({'error': 'Uploaded image exceeds maximum size limit of 10 MB.'}), 413
    except Exception as e:
        return jsonify({'error': f'Failed to read uploaded file: {str(e)}'}), 400

    # OCR Extraction
    extracted_text = _extract_text_from_image(file_bytes, current_app)

    if extracted_text is None:
        return jsonify({
            'error': 'OCR engine is not configured. Please install Tesseract OCR and set TESSERACT_CMD in your .env file.',
            'setup_hint': 'Download Tesseract from: https://github.com/UB-Mannheim/tesseract/wiki'
        }), 503

    extract_only = request.form.get('extract_only', 'false').lower() == 'true'

    if extract_only:
        return jsonify({
            'extracted_text': extracted_text,
            'char_count': len(extracted_text),
            'status': 'Text extracted successfully. Please review before scanning.'
        }), 200

    # Full analysis on extracted text
    from backend.services.text_analyzer import analyze_text_indicators, normalize_text
    from backend.ml.predict import predict_message

    normalized = normalize_text(extracted_text)
    indicators, flags = analyze_text_indicators(normalized)
    ml_result = predict_message(normalized)

    risk = calculate_risk(
        input_type='screenshot',
        indicators=indicators,
        ml_result=ml_result,
        features=flags,
        raw_input=normalized
    )

    # Record scan
    try:
        record_scan(
            scan_type='screenshot',
            risk_category=risk['risk_category'],
            risk_score=risk['risk_score'],
            indicators=risk['indicators'],
            recommendations=risk.get('recommendations', []),
            target_snippet=normalized[:80],
            db_path=current_app.config.get('DATABASE_PATH')
        )
    except Exception as e:
        current_app.logger.warning(f'Screenshot scan record failed (non-critical): {e}')

    return jsonify({
        'extracted_text': extracted_text,
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
        'channel': 'screenshot'
    }), 200


def _extract_text_from_image(file_bytes: bytes, app) -> str | None:
    """
    Uses pytesseract to extract text from image bytes.
    Returns None if tesseract is not installed or not configured.
    """
    try:
        import pytesseract
        from PIL import Image

        # Set tesseract binary path if configured
        tesseract_cmd = app.config.get('TESSERACT_CMD', '')
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

        image = Image.open(io.BytesIO(file_bytes))

        # Convert to RGB if necessary (handles PNG with alpha channel)
        if image.mode not in ('RGB', 'L'):
            image = image.convert('RGB')

        text = pytesseract.image_to_string(image, config='--psm 6')
        return text.strip()

    except ImportError:
        app.logger.warning('pytesseract or Pillow not installed.')
        return None
    except pytesseract.TesseractNotFoundError:
        app.logger.warning('Tesseract OCR engine not found on system PATH.')
        return None
    except Exception as e:
        app.logger.error(f'OCR extraction error: {e}')
        return None
