from flask import Flask, jsonify
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app)

    # Import and register your OTP Blueprint
    from .routes import bp as otp_bp
    app.register_blueprint(otp_bp)

    # Add a root route for health check / homepage
    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "status": "success",
            "message": "OTP API is live 🚀",
            "available_endpoints": [
                "/request-otp",
                "/verify-otp",
                "/login-password",
                "/admin-login",
                "/set-password",
                "/forgot-password",
                "/reset-password"
            ]
        })

    return app
