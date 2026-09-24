"""
Flask Application Factory and Entry Point.
Secure Coding Vulnerability Demonstration and Mitigation System.
"""
from flask import Flask
import config
from routes.main_routes import main_bp
from routes.command_routes import command_bp
from routes.file_routes import file_bp
from routes.auth_routes import auth_bp
from routes.exception_routes import exception_bp
from routes.temp_routes import temp_bp
from routes.dependency_routes import dependency_bp


def create_app(test_config=None):
    """Application factory for configuring and initializing the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config)

    if test_config:
        app.config.update(test_config)

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(command_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(exception_bp)
    app.register_blueprint(temp_bp)
    app.register_blueprint(dependency_bp)

    # Global HTTP Security Headers (Defense in Depth)
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com;"
        return response

    return app


app = create_app()

if __name__ == "__main__":
    print("=" * 70)
    print(" SECURE CODING ASSIGNMENT 1 - DEMO APPLICATION")
    print(" Running at: http://127.0.0.1:5000")
    print(" Note: Vulnerable endpoints are strictly sandboxed for education.")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=config.DEBUG)
