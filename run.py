"""
Server Entrypoint
Starts development WSGI server for the Flask Google Auth API.
"""

import os
import sys
from app import create_app
from app.config import Config

# Ensure UTF-8 console output on Windows (prevents cp1252 UnicodeEncodeError)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

app = create_app(Config)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = Config.DEBUG
    print("=" * 65)
    print("🚀 Shared Multi-App Flask Authentication Server Starting...")
    print(f"📡 Port: http://0.0.0.0:{port}")
    print(f"🔧 Environment: {Config.ENV}")
    print(f"🔑 Allowed Google Client IDs: {len(Config.GOOGLE_CLIENT_IDS)} configured")
    print(f"📱 Default App Key: {Config.DEFAULT_APP_KEY}")
    print("=" * 65)
    app.run(host='0.0.0.0', port=port, debug=debug)
