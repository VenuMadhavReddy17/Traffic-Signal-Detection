#!/usr/bin/env python3
"""Entry point for running the Traffic Signal Detection application."""

from app.main import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
