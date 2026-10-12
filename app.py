"""
app.py
------
Application entry point. Run with:  python app.py
Then visit http://localhost:5000 in your browser.

Before first run, initialize the database with:  python database.py
And create demo accounts with:                    python seed_demo_data.py
"""

import os

from flask import Flask

from auth import auth_bp
from admin import admin_bp
from tracking import tracking_bp
from branding import branding_bp


def create_app():
    app = Flask(__name__)
    # SECRET_KEY signs the session cookie. In production, set this via an
    # environment variable rather than hardcoding it.
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(tracking_bp)
    app.register_blueprint(branding_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
