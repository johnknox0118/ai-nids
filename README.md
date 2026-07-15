# AI-NIDS — AI-Based Network Intrusion Detection & Monitoring System

## Quick Start (Local)
```bash
git clone <repo-url>
cd ai-nids
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000 — login: admin / admin123

## Deploy to Render
1. Push to GitHub
2. New Web Service on Render → connect repo
3. Build: `pip install -r requirements.txt`
4. Start: `gunicorn app:app`
5. Add env vars: SECRET_KEY, FLASK_DEBUG=false, ADMIN_USERNAME, ADMIN_PASSWORD, RENDER=true
