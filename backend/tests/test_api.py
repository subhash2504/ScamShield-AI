import pytest
import json
from backend.app import create_app
from backend.config import TestingConfig


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_health_endpoint(client):
    """Test health check returns 200 and expected payload."""
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert data['database_connected'] is True
    assert data['ml_model_active'] is True


def test_analyze_message_phishing(client):
    """Test message scanner with a typical phishing lure."""
    payload = {
        "message": "URGENT: Your bank account is locked! Click http://fake-bank-login.xyz to verify your identity now."
    }
    response = client.post('/api/analyze/message',
                           data=json.dumps(payload),
                           content_type='application/json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'risk_score' in data
    assert 'risk_category' in data
    assert data['risk_category'] in ['Medium Risk', 'High Risk']
    assert data['risk_score'] >= 40
    assert len(data['indicators']) > 0


def test_analyze_message_benign(client):
    """Test message scanner with a normal everyday message."""
    payload = {
        "message": "Hey, let's meet up for coffee tomorrow afternoon at 3pm."
    }
    response = client.post('/api/analyze/message',
                           data=json.dumps(payload),
                           content_type='application/json')
    assert response.status_code == 200
    data = response.get_json()
    assert data['risk_category'] in ['Low Risk', 'Unable to Determine']


def test_analyze_message_empty(client):
    """Test empty message validation."""
    response = client.post('/api/analyze/message',
                           data=json.dumps({"message": ""}),
                           content_type='application/json')
    assert response.status_code == 400


def test_analyze_url_suspicious(client):
    """Test URL scanner with high risk domain."""
    payload = {"url": "http://paypal.com.verify-account-update.tk/login"}
    response = client.post('/api/analyze/url',
                           data=json.dumps(payload),
                           content_type='application/json')
    assert response.status_code == 200
    data = response.get_json()
    assert data['risk_score'] >= 50
    assert len(data['indicators']) > 0


def test_analyze_url_empty(client):
    """Test empty URL validation."""
    response = client.post('/api/analyze/url',
                           data=json.dumps({"url": ""}),
                           content_type='application/json')
    assert response.status_code == 400


def test_analyze_email_bec(client):
    """Test email scanner detecting BEC patterns."""
    payload = {
        "sender": "CEO Office <ceo-urgent@mail-outlook-exec.com>",
        "subject": "URGENT: Wire transfer required",
        "body": "Please wire $50,000 to the escrow account immediately."
    }
    response = client.post('/api/analyze/email',
                           data=json.dumps(payload),
                           content_type='application/json')
    assert response.status_code == 200
    data = response.get_json()
    assert data['risk_category'] in ['High Risk', 'Medium Risk']
    assert len(data['indicators']) > 0


def test_dashboard_stats_and_scans(client):
    """Test retrieval of dashboard statistics and scan history."""
    stats_res = client.get('/api/dashboard/stats')
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert 'total_scans' in stats
    assert 'risk_distribution' in stats

    scans_res = client.get('/api/scans')
    assert scans_res.status_code == 200
    scans_data = scans_res.get_json()
    assert 'scans' in scans_data
