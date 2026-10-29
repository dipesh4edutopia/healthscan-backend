"""
Flask Application Factory
Initializes Flask app, registers blueprints, configures CORS, and formats error responses.
"""

import logging
from datetime import datetime, timezone
from flask import Flask, jsonify
from flask_cors import CORS

from app.config import Config
from app.routes.auth_routes import auth_bp
from app.database import init_db_pool, close_db_pool, get_db_cursor

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)


def create_app(config_class=Config) -> Flask:
    """
    Creates and configures the Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable Cross-Origin Resource Sharing (CORS) for Expo and mobile clients
    CORS(
        app,
        resources={r"/api/*": {"origins": config_class.CORS_ORIGINS}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-App-Key", "User-Agent"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )

    # Register authentication blueprint
    app.register_blueprint(auth_bp)

    # Public liveness & DB connectivity health check
    @app.route('/api/v1/health', methods=['GET'])
    def health_check():
        db_status = "untested"
        try:
            with get_db_cursor(commit=False) as cursor:
                cursor.execute("SELECT 1 AS alive;")
                row = cursor.fetchone()
                if row and row.get('alive') == 1:
                    db_status = "connected"
        except Exception as e:
            db_status = f"unreachable ({e.__class__.__name__})"

        return jsonify({
            'status': 'healthy',
            'service': 'Shared Multi-App Flask Auth API',
            'database': db_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }), 200

    # Global JSON error handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({
            'error': 'BadRequest',
            'message': str(getattr(e, 'description', 'Invalid request syntax or parameters.')),
        }), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({
            'error': 'NotFound',
            'message': 'The requested resource was not found on this server.',
        }), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        return jsonify({
            'error': 'MethodNotAllowed',
            'message': 'The HTTP method is not allowed for this endpoint.',
        }), 405

    @app.errorhandler(500)
    def handle_server_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected server error occurred.',
        }), 500

    # Initialize connection pool if not testing
    if not getattr(config_class, 'TESTING', False):
        try:
            init_db_pool()
        except Exception as e:
            logger.warning(f"Could not connect to database on startup: {e}")

    # Register teardown
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        pass

    return app
