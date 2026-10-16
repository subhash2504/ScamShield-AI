"""
PhishGuard AI - Dashboard & Analytics Routes
Handles scan statistics, recent scan history, and ML model metrics endpoints.
"""
import json
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from backend.database.db import get_scan_stats, get_recent_scans, clear_scans

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard/stats', methods=['GET'])
def get_stats():
    """
    Returns aggregate security telemetry statistics for the analytics dashboard.
    Includes risk distribution, channel breakdown, weekly trends, and ML model metrics.
    """
    try:
        stats = get_scan_stats(db_path=current_app.config.get('DATABASE_PATH'))
    except Exception as e:
        current_app.logger.error(f'Failed to fetch dashboard stats: {e}')
        return jsonify({'error': 'Failed to retrieve dashboard statistics.', 'detail': str(e)}), 500

    # Attach ML model evaluation metrics if available
    ml_metrics = _load_ml_metrics(current_app)

    return jsonify({
        **stats,
        'ml_metrics': ml_metrics,
        'ml_model_active': _is_model_active(current_app)
    }), 200


@dashboard_bp.route('/scans', methods=['GET'])
def get_scans():
    """
    Returns a paginated list of recent scan records for the dashboard table.
    Query params: ?limit=50 (max 200)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    try:
        scans = get_recent_scans(limit=limit, db_path=current_app.config.get('DATABASE_PATH'))
    except Exception as e:
        current_app.logger.error(f'Failed to fetch recent scans: {e}')
        return jsonify({'error': 'Failed to retrieve scan records.'}), 500

    return jsonify({
        'scans': scans,
        'count': len(scans),
        'limit': limit
    }), 200


@dashboard_bp.route('/scans', methods=['DELETE'])
def delete_scans():
    """
    Purges all scan records from the database.
    Requires confirmation via the client UI.
    """
    try:
        deleted_count = clear_scans(db_path=current_app.config.get('DATABASE_PATH'))
    except Exception as e:
        current_app.logger.error(f'Failed to clear scans: {e}')
        return jsonify({'error': 'Failed to purge scan history.'}), 500

    return jsonify({
        'message': f'Successfully purged {deleted_count} scan record(s) from the database.',
        'deleted_count': deleted_count
    }), 200


def _load_ml_metrics(app) -> dict | None:
    """
    Loads stored ML evaluation metrics from disk if the model has been trained.
    Returns None if not available (model binary not yet trained).
    """
    metrics_path = Path(app.config.get('ML_METRICS_PATH', ''))
    if not metrics_path or not metrics_path.exists():
        return None

    try:
        with open(metrics_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Validate expected keys before returning
        expected = {'accuracy', 'precision', 'recall', 'f1'}
        if expected.issubset(data.keys()):
            return data
    except Exception as e:
        app.logger.warning(f'Could not load ML metrics file: {e}')

    return None


def _is_model_active(app) -> bool:
    """Checks whether the trained ML model binary exists on disk."""
    model_path = Path(app.config.get('ML_MODEL_PATH', ''))
    return model_path.exists() if model_path else False
