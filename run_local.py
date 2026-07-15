"""
run_local.py — Launch AI-NIDS with REAL network scanning on your local machine.

Usage:
  Windows (PowerShell as Administrator):
    python run_local.py

  Mac/Linux (terminal):
    sudo python3 run_local.py

Why admin/root?
  Raw packet capture (Scapy) requires low-level network access.
  Without it the app still works but uses simulated traffic.
"""
import os
import sys
import subprocess

# ── Set environment for local real-network mode ──────────────
os.environ['FLASK_DEBUG']      = 'false'
os.environ['ADMIN_USERNAME']   = os.environ.get('ADMIN_USERNAME', 'admin')
os.environ['ADMIN_PASSWORD']   = os.environ.get('ADMIN_PASSWORD', 'admin123')
os.environ['SECRET_KEY']       = os.environ.get('SECRET_KEY', 'local-dev-key-change-me')
# Do NOT set RENDER=true → app will try real Scapy capture

print("=" * 55)
print("  AI-NIDS — Local Network Scanner")
print("=" * 55)

# Check if running as admin/root
if sys.platform == 'win32':
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
else:
    is_admin = os.geteuid() == 0

if is_admin:
    print("✓ Running as Administrator/root")
    print("✓ Real packet capture: ENABLED")
    print("✓ Will scan your actual network traffic")
else:
    print("⚠ Not running as Administrator/root")
    print("⚠ Real packet capture: DISABLED (needs admin/root)")
    print("⚠ Will use traffic simulator instead")
    print()
    if sys.platform == 'win32':
        print("  To enable real scanning:")
        print("  Right-click PowerShell → Run as Administrator")
        print("  Then: python run_local.py")
    else:
        print("  To enable real scanning:")
        print("  sudo python3 run_local.py")

print()
print("  Open: http://localhost:5000")
print("  Login: admin / admin123")
print("  Press Ctrl+C to stop")
print("=" * 55)
print()

# Import and run directly (avoids gunicorn overhead for local dev)
from app import app
import capture, config

port = int(os.environ.get('PORT', 5000))
app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
