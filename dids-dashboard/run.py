#!/usr/bin/env python3
"""
Simple entry point for running the DIDS application.
"""
import os

from app import create_app

# Get environment configuration
env = os.environ.get("FLASK_ENV", "development")

# Create application instance
app = create_app(env)

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 8000))
    debug = env == "development"

    print(
        f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║  Distributed Intrusion Detection System (DIDS)            ║
    ║  Running in {env.upper():11s} mode                            ║
    ║  Server: http://{host}:{port}                             ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    )

    app.run(host=host, port=port, debug=debug, use_reloader=False)
