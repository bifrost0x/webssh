import warnings
# Suppress Paramiko's TripleDES deprecation warnings
warnings.filterwarnings('ignore', message='.*TripleDES.*', category=DeprecationWarning)

from app import create_app, socketio
import config
import os

app = create_app()

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    print("Starting Web SSH Terminal...")
    print(f"Server running at http://{host}:{port}")
    print("Press Ctrl+C to stop the server")

    socketio.run(
        app,
        host=host,
        port=port,
        debug=config.DEBUG
    )
