import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flask
SECRET_KEY     = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
DEBUG          = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

# Admin bootstrap (first run only)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# On Render free tier only /tmp is writable at runtime
IS_RENDER   = bool(os.environ.get('RENDER', ''))
RUNTIME_DIR = '/tmp/nids' if IS_RENDER else BASE_DIR

# All runtime paths
DATABASE    = os.path.join(RUNTIME_DIR, 'logs', 'nids.db')
MODEL_PATH  = os.path.join(RUNTIME_DIR, 'models', 'attack_model.pkl')
MODELS_DIR  = os.path.join(RUNTIME_DIR, 'models')
REPORTS_DIR = os.path.join(RUNTIME_DIR, 'reports')

# Detection thresholds
PORT_SCAN_THRESHOLD    = 100
PING_FLOOD_THRESHOLD   = 1000
BRUTE_FORCE_THRESHOLD  = 50
LARGE_PACKET_THRESHOLD = 1500

# Pagination
PACKETS_PER_PAGE = 50
