import os
import sys
from pathlib import Path
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import get_config, FRONTEND_DIR
from backend.database.db import init_db

def create_app(config_class=None):
    """Application factory for PhishGuard AI."""
    if config_class is None:
        config_class = get_config()

    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )
    app.config.from_object(config_class)

    # Enable CORS for cross-origin frontend clients if hosted independently
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Request size limit configuration
    app.config['MAX_CONTENT_LENGTH'] = config_class.MAX_CONTENT_LENGTH

    # Initialize Database Schema
    try:
        init_db(app.config.get("DATABASE_PATH"))
    except Exception as e:
        app.logger.warning(f"Database initialization notice: {e}")

    # Register Blueprints
    from backend.routes.message_routes import message_bp
    from backend.routes.url_routes import url_bp
    from backend.routes.dashboard_routes import dashboard_bp

    app.register_blueprint(message_bp, url_prefix="/api")
    app.register_blueprint(url_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/api")

    # Static Frontend Serving
    @app.route("/")
    def serve_index():
        return send_from_directory(str(FRONTEND_DIR), "index.html")

    @app.route("/dashboard")
    @app.route("/dashboard.html")
    def serve_dashboard():
        return send_from_directory(str(FRONTEND_DIR), "dashboard.html")

    # API Health Endpoint
    @app.route("/api/health", methods=["GET"])
    def health_check():
        db_ok = True
        try:
            from backend.database.db import get_db_connection
            conn = get_db_connection(app.config.get("DATABASE_PATH"))
            conn.cursor().execute("SELECT 1")
            conn.close()
        except Exception:
            db_ok = False

        ml_model_loaded = Path(app.config.get("ML_MODEL_PATH", "")).exists()

        return jsonify({
            "status": "healthy",
            "service": "PhishGuard AI Core Engine",
            "version": "1.0.0",
            "database_connected": db_ok,
            "ml_model_active": ml_model_loaded,
            "security_features": {
                "zero_execution_url_parsing": True,
                "pii_message_redaction": True,
                "multi_factor_risk_scoring": True
            }
        }), 200

    # Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({"error": "Bad request", "message": str(e)}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found"}), 404
        return send_from_directory(str(FRONTEND_DIR), "index.html"), 200

    @app.errorhandler(413)
    def handle_large_file(e):
        return jsonify({"error": "Payload too large", "message": "Uploaded file exceeds maximum limit of 10 MB"}), 413

    @app.errorhandler(429)
    def handle_rate_limit(e):
        return jsonify({"error": "Rate limit exceeded", "message": "Too many requests. Please wait a moment."}), 429

    @app.errorhandler(500)
    def handle_internal_error(e):
        return jsonify({"error": "Internal server error", "message": "An error occurred during threat analysis."}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"[*] Starting PhishGuard AI platform on http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
