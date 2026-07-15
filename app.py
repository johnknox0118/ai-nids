"""
AI-NIDS — All HTML embedded in Python. Zero template-file dependency.
Fixes: background ML training, DB corruption auto-recovery, instant stop button.
"""
import os, hashlib, traceback, threading
from functools import wraps
from flask import Flask, request, redirect, url_for, session, jsonify, send_file

import config
import database as db
import capture
import ml_model
import reports as rpt

app            = Flask(__name__)
app.secret_key = config.SECRET_KEY


# ═══════════════════════════════════════════════════════════
# BOOTSTRAP
# The ONLY safe order on Render:
#   1. Create dirs
#   2. Verify + repair DB (BEFORE init_db)
#   3. init_db (now safe to write)
#   4. ML training in BACKGROUND THREAD (never blocks gunicorn)
#   5. Start capture
# ═══════════════════════════════════════════════════════════
def _bootstrap():
    # Step 1 — directories
    for folder in [
        os.path.join(config.RUNTIME_DIR, 'logs'),
        os.path.join(config.RUNTIME_DIR, 'reports'),
        os.path.join(config.RUNTIME_DIR, 'models'),
        os.path.join(config.RUNTIME_DIR, 'uploads'),
    ]:
        os.makedirs(folder, exist_ok=True)

    # Step 2 — verify and repair DB BEFORE touching it
    db.verify_and_repair()

    # Step 3 — init DB (safe now)
    try:
        db.init_db()
    except Exception as e:
        print(f"[Bootstrap] init_db failed ({e}) — retrying after delete")
        try:
            os.remove(config.DATABASE)
        except Exception:
            pass
        try:
            db.init_db()
        except Exception as e2:
            print(f"[Bootstrap] DB rebuild failed: {e2}")

    # Step 4 — ML training in background (CRITICAL — avoids gunicorn timeout)
    def _train_bg():
        if not os.path.exists(config.MODEL_PATH):
            print("[ML] Training in background thread (won't block gunicorn)...")
            try:
                ml_model.train_model('random_forest')
                print("[ML] Background training complete.")
            except Exception as e:
                print(f"[ML] Training failed: {e}")

    threading.Thread(target=_train_bg, daemon=True).start()

    # Step 5 — start capture
    # On Render cloud (IS_RENDER=true): use simulator (no root/libpcap available)
    # On local machine: auto-detect and use real network capture
    use_real = not config.IS_RENDER
    try:
        capture.start_capture(use_scapy=use_real)
        if use_real:
            print(f"[Startup] Real network capture — interface: {capture.get_interface()}, your IP: {capture.get_local_ip()}")
        else:
            print("[Startup] Cloud mode — using traffic simulator")
    except Exception as e:
        print(f"[Startup] Capture error: {e} — falling back to simulator")
        try:
            capture.start_capture(use_scapy=False)
        except Exception:
            pass

_bootstrap()


# ═══════════════════════════════════════════════════════════
# CSS
# ═══════════════════════════════════════════════════════════
_CSS = """<style>
:root{--bg:#0b0f1a;--bg2:#111827;--card:#151c2c;--card2:#1a2236;
  --border:#232c42;--txt:#e8ecf4;--txt2:#8b94ab;--muted:#5d6680;
  --blue:#3b82f6;--cyan:#06b6d4;--green:#10b981;--yellow:#f59e0b;
  --orange:#fb923c;--red:#ef4444;--purple:#8b5cf6;--sidebar:240px}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:Inter,-apple-system,sans-serif;font-size:14px}
a{text-decoration:none}
.shell{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar);background:var(--bg2);border-right:1px solid var(--border);
  position:fixed;top:0;left:0;bottom:0;display:flex;flex-direction:column;padding:24px 0;z-index:100}
.brand{display:flex;align-items:center;gap:10px;padding:0 24px 20px;font-size:18px;font-weight:800;
  border-bottom:1px solid var(--border);margin-bottom:12px}
.brand-icon{color:var(--cyan);font-size:22px}
.nav-links{list-style:none;flex:1}
.nav-links li a{display:flex;align-items:center;gap:12px;padding:11px 24px;color:var(--txt2);
  font-weight:500;font-size:13.5px;border-left:3px solid transparent;transition:.15s}
.nav-links li a:hover{background:var(--card);color:var(--txt)}
.nav-links li a.active{background:rgba(59,130,246,.1);color:var(--blue);border-left-color:var(--blue)}
.nav-icon{width:18px;text-align:center;display:inline-block}
.sidebar-foot{padding:16px 24px 0;border-top:1px solid var(--border);margin-top:16px}
.user-chip{display:flex;align-items:center;gap:8px;font-weight:600;margin-bottom:10px}
.logout-a{color:var(--muted);font-size:13px;display:flex;align-items:center;gap:8px}
.logout-a:hover{color:var(--red)}
.main{margin-left:var(--sidebar);flex:1;padding:28px 32px}
.flash-stack{margin-bottom:20px}
.flash{padding:12px 16px;border-radius:8px;margin-bottom:8px;display:flex;align-items:center;gap:10px;font-weight:500;font-size:13.5px}
.flash-success{background:rgba(16,185,129,.12);color:var(--green);border:1px solid rgba(16,185,129,.25)}
.flash-error{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.25)}
.ph{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.pt{font-size:24px;font-weight:800}.ps{color:var(--txt2);font-size:13.5px;margin-top:4px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.sc{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.si{width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:14px}
.sv{font-size:28px;font-weight:800;font-family:monospace;line-height:1;margin-bottom:4px}
.sl{color:var(--txt2);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.sb .si{background:rgba(59,130,246,.15);color:var(--blue)}
.sr .si{background:rgba(239,68,68,.15);color:var(--red)}
.sy .si{background:rgba(245,158,11,.15);color:var(--yellow)}
.sg2 .si{background:rgba(16,185,129,.15);color:var(--green)}
.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px}
.ptitle{font-size:15px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between}
.ptitle .rt{font-size:12px;font-weight:500;color:var(--muted)}
.g2{display:grid;grid-template-columns:1.4fr 1fr;gap:20px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
@media(max-width:1100px){.g2,.g3{grid-template-columns:1fr}}
.tw{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:10px 12px;color:var(--muted);font-weight:600;font-size:11px;
  text-transform:uppercase;letter-spacing:.03em;border-bottom:1px solid var(--border)}
.tbl td{padding:10px 12px;border-bottom:1px solid var(--border)}
.tbl tbody tr:hover{background:var(--card2)}
.mono{font-family:monospace;font-size:12.5px}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase}
.bc{background:rgba(239,68,68,.15);color:var(--red)}.bh{background:rgba(251,146,60,.15);color:var(--orange)}
.bm{background:rgba(245,158,11,.15);color:var(--yellow)}.bl{background:rgba(16,185,129,.15);color:var(--green)}
.bn{background:rgba(59,130,246,.12);color:var(--blue)}.bt{background:rgba(239,68,68,.15);color:var(--red)}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 18px;border-radius:8px;
  font-weight:600;font-size:13px;cursor:pointer;border:none;transition:.15s;color:#fff}
.btn-p{background:var(--blue)}.btn-p:hover{background:#2563eb}
.btn-o{background:transparent;border:1px solid var(--border);color:var(--txt)}.btn-o:hover{background:var(--card2)}
.btn-d{background:var(--red)}.btn-d:hover{background:#dc2626}
.btn-s{background:var(--green)}.btn-s:hover{background:#059669}
.btn-sm{padding:5px 12px;font-size:12px}
.fc{background:var(--bg2);border:1px solid var(--border);color:var(--txt);
  padding:9px 12px;border-radius:8px;font-size:13.5px;width:100%}
.fc:focus{outline:none;border-color:var(--blue)}
.fl{font-size:12.5px;font-weight:600;color:var(--txt2);margin-bottom:6px;display:block}
.fg{margin-bottom:16px}
.pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);
  margin-right:6px;animation:pulse 1.5s infinite}
.pulse.off{background:var(--muted);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(16,185,129,.5)}70%{box-shadow:0 0 0 8px rgba(16,185,129,0)}100%{box-shadow:0 0 0 0 rgba(16,185,129,0)}}
.pages{display:flex;gap:6px;justify-content:center;margin-top:16px}
.pages a,.pages span{padding:6px 12px;border-radius:6px;border:1px solid var(--border);color:var(--txt2);font-size:12.5px}
.pages a:hover{background:var(--card2)}.pages .cur{background:var(--blue);color:#fff;border-color:var(--blue)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.empty{text-align:center;padding:40px;color:var(--muted)}
.lw{min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(circle at 20% 20%,rgba(59,130,246,.12),transparent 50%),
  radial-gradient(circle at 80% 80%,rgba(139,92,246,.1),transparent 50%),var(--bg)}
.lc{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:40px;width:380px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.ll{text-align:center;margin-bottom:24px}
.ll h1{font-size:20px;font-weight:800;margin:10px 0 4px}
.ll p{color:var(--txt2);font-size:12.5px}
</style>"""

_CDN = """
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>"""


def _head(title):
    return f"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title} | AI-NIDS</title>{_CDN}{_CSS}</head><body>"


def _sidebar(active):
    links = [
        ('dashboard',    'fa-gauge-high',         'Dashboard'),
        ('packets',      'fa-network-wired',       'Packet Monitor'),
        ('alerts',       'fa-triangle-exclamation','Threats &amp; Alerts'),
        ('reports_page', 'fa-file-lines',          'Reports'),
        ('logs_viewer',  'fa-list-check',          'Logs Viewer'),
        ('settings',     'fa-gear',                'Settings'),
    ]
    items = ""
    for ep, icon, label in links:
        cls = "active" if active == ep else ""
        items += f'<li><a href="{url_for(ep)}" class="{cls}"><span class="nav-icon"><i class="fa-solid {icon}"></i></span> {label}</a></li>'
    user = session.get('username', 'Admin')
    return f"""<nav class="sidebar">
      <div class="brand"><span class="brand-icon"><i class="fa-solid fa-shield-halved"></i></span> AI-NIDS</div>
      <ul class="nav-links">{items}</ul>
      <div class="sidebar-foot">
        <div class="user-chip"><i class="fa-solid fa-circle-user" style="color:var(--cyan);font-size:20px"></i> {user}</div>
        <a href="{url_for('logout')}" class="logout-a"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
      </div></nav>"""


def _flash_html():
    msgs = session.pop('_flashes', [])
    if not msgs: return ""
    html = '<div class="flash-stack">'
    for cat, msg in msgs:
        icon = "fa-circle-check" if cat == "success" else "fa-circle-exclamation"
        html += f'<div class="flash flash-{cat}"><i class="fa-solid {icon}"></i> {msg}</div>'
    return html + '</div>'


def _flash(cat, msg):
    f = session.get('_flashes', [])
    f.append((cat, msg))
    session['_flashes'] = f


def _page(active, title, body, extra_js=""):
    return (_head(title) + '<div class="shell">' + _sidebar(active) +
            '<main class="main">' + _flash_html() + body +
            '</main></div>' + extra_js + '</body></html>')


# ═══ AUTH ══════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        try:
            # Auto-repair DB before login attempt
            db.verify_and_repair()
            conn = db.get_db()
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
                session['user_id']  = user['id']
                session['username'] = user['username']
                session['role']     = user['role']
                if request.form.get('remember'):
                    session.permanent = True
                return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"[Login] Error: {e} — attempting DB recovery")
            try:
                os.remove(config.DATABASE)
                db.init_db()
                error = '<div class="flash flash-error"><i class="fa-solid fa-circle-exclamation"></i> Database was reset — please try logging in again</div>'
            except Exception as e2:
                print(f"[Login] Recovery failed: {e2}")
                error = '<div class="flash flash-error"><i class="fa-solid fa-circle-exclamation"></i> Server error — please refresh and try again</div>'
        if not error:
            error = '<div class="flash flash-error"><i class="fa-solid fa-circle-exclamation"></i> Invalid username or password</div>'

    html = f"""{_head('Login')}<div class="lw"><div class="lc">
      <div class="ll">
        <div style="font-size:40px;color:var(--cyan)"><i class="fa-solid fa-shield-halved"></i></div>
        <h1>AI-NIDS</h1><p>Network Intrusion Detection &amp; Monitoring</p>
      </div>
      {error}
      <form method="POST">
        <div class="fg"><label class="fl">Username</label>
          <input type="text" name="username" class="fc" placeholder="admin" required autofocus></div>
        <div class="fg"><label class="fl">Password</label>
          <input type="password" name="password" class="fc" placeholder="••••••••" required></div>
        <div class="d-flex justify-content-between align-items-center mb-3" style="font-size:12.5px;color:var(--txt2)">
          <label class="d-flex align-items-center gap-2"><input type="checkbox" name="remember"> Remember Me</label>
        </div>
        <button type="submit" class="btn btn-p w-100 justify-content-center">
          <i class="fa-solid fa-right-to-bracket"></i> Login</button>
      </form>
      <p class="text-center mt-3" style="color:var(--muted);font-size:12px">
        Default: <span class="mono">admin / admin123</span></p>
    </div></div></body></html>"""
    return html


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ═══ DASHBOARD ═════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard():
    stats    = db.get_stats()
    proto    = db.get_protocol_stats()
    timeline = db.get_threat_timeline()
    freq     = db.get_attack_frequency()
    cap_on   = capture.is_running()
    minfo    = ml_model.get_model_info()
    ml_txt   = (f"{minfo['algorithm'].replace('_',' ').title()} · {minfo['accuracy']*100:.1f}% accuracy"
                if minfo else "Training in background…")
    pulse_cls = "pulse" if cap_on else "pulse off"
    mode_txt  = capture.get_mode()
    iface_txt = capture.get_interface() or ''
    local_ip  = capture.get_local_ip()

    proto_labels = list(proto.keys())
    proto_values = list(proto.values())
    tl_labels    = [d['day'] for d in reversed(timeline)]
    tl_values    = [d['cnt'] for d in reversed(timeline)]
    fq_labels    = [d['attack_name'] for d in freq]
    fq_values    = [d['cnt'] for d in freq]

    body = f"""
    <div class="ph">
      <div><h1 class="pt">Security Operations Dashboard</h1>
        <p class="ps"><span class="{pulse_cls}"></span>{'● Live' if cap_on else '○ Stopped'} &nbsp;·&nbsp; {mode_txt}{f' — {iface_txt}' if iface_txt else ''} &nbsp;·&nbsp; ML: {ml_txt}</p>
        <p class="ps" style="color:var(--cyan);font-size:12px">Your IP: {local_ip}</p>
      </div>
      <div class="d-flex gap-2">
        <button class="btn btn-s" id="btnStart" data-bs-toggle="modal" data-bs-target="#captureModal"><i class="fa-solid fa-play"></i> Start Capture</button>
        <button class="btn btn-d" id="btnStop"><i class="fa-solid fa-stop"></i> Stop</button>
      </div>
    </div>
    <div class="sg">
      <div class="sc sb"><div class="si"><i class="fa-solid fa-database"></i></div><div class="sv" id="sPkts">{stats['total_packets']}</div><div class="sl">Total Packets</div></div>
      <div class="sc sr"><div class="si"><i class="fa-solid fa-bug"></i></div><div class="sv" id="sThreats">{stats['total_threats']}</div><div class="sl">Detected Threats</div></div>
      <div class="sc sy"><div class="si"><i class="fa-solid fa-bell"></i></div><div class="sv" id="sAlerts">{stats['today_alerts']}</div><div class="sl">Today's Alerts</div></div>
      <div class="sc sg2"><div class="si"><i class="fa-solid fa-ban"></i></div><div class="sv" id="sBlocked">{stats['blocked_ips']}</div><div class="sl">Blocked IPs</div></div>
    </div>
    <div class="g2">
      <div class="panel"><div class="ptitle">Live Traffic <span class="rt" id="liveCnt"></span></div><canvas id="cTraffic" height="110"></canvas></div>
      <div class="panel"><div class="ptitle">Protocol Distribution</div><canvas id="cProto" height="110"></canvas></div>
    </div>
    <div class="g2">
      <div class="panel"><div class="ptitle">Threat Timeline (7 days)</div><canvas id="cTime" height="110"></canvas></div>
      <div class="panel"><div class="ptitle">Attack Frequency</div><canvas id="cFreq" height="110"></canvas></div>
    </div>
    <div class="panel">
      <div class="ptitle">Live Packet Stream</div>
      <div class="tw"><table class="tbl">
        <thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Protocol</th><th>Size</th><th>Status</th></tr></thead>
        <tbody id="liveTbody"><tr><td colspan="6" class="empty">Waiting for traffic…</td></tr></tbody>
      </table></div>
    </div>

    <!-- Capture Mode Modal -->
    <div class="modal fade" id="captureModal" tabindex="-1">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content" style="background:var(--card);border:1px solid var(--border);border-radius:12px">
          <div class="modal-header" style="border-bottom:1px solid var(--border)">
            <h5 class="modal-title" style="color:var(--txt);font-weight:700">
              <i class="fa-solid fa-network-wired" style="color:var(--cyan)"></i> Start Packet Capture
            </h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <div id="captureOptions">
              <div style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:8px;padding:14px;margin-bottom:14px;cursor:pointer" onclick="startCapture(true)" id="optReal">
                <div style="font-weight:700;color:var(--green);margin-bottom:4px">
                  <i class="fa-solid fa-wifi"></i> Real Network Scan (Recommended)
                </div>
                <div style="font-size:12.5px;color:var(--txt2)">
                  Scans actual network traffic on your device's interface.<br>
                  <strong style="color:var(--yellow)">⚠ Requires: Run as Administrator (Windows) or sudo (Mac/Linux)</strong>
                </div>
                <div style="margin-top:10px">
                  <label style="font-size:12px;color:var(--txt2);display:block;margin-bottom:4px">Network Interface (optional — auto-detects if empty):</label>
                  <select id="ifaceSelect" class="fc" style="font-size:12.5px" onclick="event.stopPropagation()">
                    <option value="">Auto-detect best interface</option>
                  </select>
                  <div id="ifaceInfo" style="font-size:11px;color:var(--cyan);margin-top:4px"></div>
                </div>
              </div>
              <div style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);border-radius:8px;padding:14px;cursor:pointer" onclick="startCapture(false)">
                <div style="font-weight:700;color:var(--blue);margin-bottom:4px">
                  <i class="fa-solid fa-flask"></i> Simulator Mode
                </div>
                <div style="font-size:12.5px;color:var(--txt2)">
                  Generates realistic fake traffic. No root/admin needed.<br>
                  Works on any device including cloud deployments.
                </div>
              </div>
            </div>
            <div id="captureStatus" style="display:none;text-align:center;padding:20px">
              <div class="spinner-border text-info" role="status"></div>
              <p style="color:var(--txt2);margin-top:12px;font-size:13.5px" id="captureStatusMsg">Starting capture…</p>
            </div>
          </div>
        </div>
      </div>
    </div>"""

    js = f"""<script>
window.onload = function() {{
  const CL=['#3b82f6','#06b6d4','#10b981','#f59e0b','#fb923c','#ef4444','#8b5cf6'];
  const CO={{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:'#5d6680'}},grid:{{display:false}}}},y:{{ticks:{{color:'#5d6680'}},grid:{{color:'#232c42'}}}}}}}};
  new Chart(document.getElementById('cProto'),{{type:'doughnut',
    data:{{labels:{proto_labels},datasets:[{{data:{proto_values},backgroundColor:CL,borderWidth:0}}]}},
    options:{{plugins:{{legend:{{position:'right',labels:{{color:'#8b94ab',boxWidth:10,font:{{size:11}}}}}}}}}}
  }});
  new Chart(document.getElementById('cTime'),{{type:'line',
    data:{{labels:{tl_labels},datasets:[{{data:{tl_values},borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.1)',fill:true,tension:.3}}]}},
    options:CO}});
  new Chart(document.getElementById('cFreq'),{{type:'bar',
    data:{{labels:{fq_labels},datasets:[{{data:{fq_values},backgroundColor:'#fb923c',borderRadius:6}}]}},
    options:CO}});
  const tChart=new Chart(document.getElementById('cTraffic'),{{type:'line',
    data:{{labels:[],datasets:[{{data:[],borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.1)',fill:true,tension:.3}}]}},
    options:{{animation:false,...CO}}}});
  function sBadge(s){{return s==='threat'?'<span class="badge bt">Threat</span>':'<span class="badge bn">Normal</span>';}}
  async function poll(){{
    try{{
      const r=await fetch('{url_for('api_live')}');const d=await r.json();
      document.getElementById('sPkts').textContent=d.stats.total_packets;
      document.getElementById('sThreats').textContent=d.stats.total_threats;
      document.getElementById('sAlerts').textContent=d.stats.today_alerts;
      document.getElementById('sBlocked').textContent=d.stats.blocked_ips;
      const pk=d.live_packets;
      document.getElementById('liveCnt').textContent=pk.length+' packets';
      if(pk.length){{document.getElementById('liveTbody').innerHTML=pk.slice(-15).reverse().map(p=>
        `<tr><td class="mono">${{p.timestamp}}</td><td class="mono">${{p.source_ip}}</td>
        <td class="mono">${{p.destination_ip}}</td><td>${{p.protocol}}</td>
        <td class="mono">${{p.packet_size}}B</td><td>${{sBadge(p.status)}}</td></tr>`).join('');}}
      const now=new Date().toLocaleTimeString();
      tChart.data.labels.push(now);tChart.data.datasets[0].data.push(pk.length);
      if(tChart.data.labels.length>20){{tChart.data.labels.shift();tChart.data.datasets[0].data.shift();}}
      tChart.update();
    }}catch(e){{}}
  }}
  setInterval(poll,2000);poll();

  // Load interfaces when modal opens
  document.getElementById('captureModal').addEventListener('show.bs.modal', async () => {{
    try {{
      const r = await fetch('{url_for('api_interfaces')}');
      const d = await r.json();
      const sel = document.getElementById('ifaceSelect');
      sel.innerHTML = '<option value="">Auto-detect best interface</option>';
      d.interfaces.forEach(iface => {{
        if(iface.ip && iface.ip !== '0.0.0.0') {{
          const opt = document.createElement('option');
          opt.value = iface.name;
          opt.textContent = `${{iface.name}} — ${{iface.ip}}`;
          if(iface.name === d.current) opt.selected = true;
          sel.appendChild(opt);
        }}
      }});
      document.getElementById('ifaceInfo').textContent =
        d.is_render ? '⚠ Cloud mode — only simulator available' :
        `Your IP: ${{d.local_ip}} · Current: ${{d.mode}}`;
      if(d.is_render) {{
        document.getElementById('optReal').style.opacity='0.4';
        document.getElementById('optReal').style.pointerEvents='none';
      }}
    }} catch(e) {{ console.error(e); }}
  }});

  // startCapture called from modal buttons
  window.startCapture = async function(useReal) {{
    document.getElementById('captureOptions').style.display='none';
    document.getElementById('captureStatus').style.display='block';
    const iface = document.getElementById('ifaceSelect').value;
    document.getElementById('captureStatusMsg').textContent =
      useReal ? `Starting real capture on ${{iface || 'auto-detected interface'}}…` : 'Starting simulator…';
    try {{
      const r = await fetch('{url_for('api_capture_start')}', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{use_real: useReal, interface: iface || null}})
      }});
      const d = await r.json();
      document.getElementById('captureStatusMsg').textContent =
        `✓ Started: ${{d.mode}}` + (d.interface ? ` (${{d.interface}})` : '');
      setTimeout(() => {{ bootstrap.Modal.getInstance(document.getElementById('captureModal')).hide(); location.reload(); }}, 1500);
    }} catch(e) {{
      document.getElementById('captureStatusMsg').textContent = 'Error starting capture. Try simulator mode.';
    }}
  }};

  document.getElementById('btnStop').onclick = async () => {{
    await fetch('{url_for('api_capture_stop')}', {{method:'POST'}});
    location.reload();
  }};
}};
</script>"""
    return _page('dashboard', 'Dashboard', body, js)


@app.route('/api/live')
@login_required
def api_live():
    return jsonify({'stats': db.get_stats(), 'live_packets': capture.get_live_packets(),
                    'recent_alerts': db.get_recent_alerts(10), 'capture_status': capture.is_running()})

@app.route('/api/capture/start', methods=['POST'])
@login_required
def api_capture_start():
    data     = request.get_json(silent=True) or {}
    use_real = data.get('use_real', not config.IS_RENDER)
    iface    = data.get('interface')
    if iface:
        os.environ['CAPTURE_INTERFACE'] = iface
    elif 'CAPTURE_INTERFACE' in os.environ:
        del os.environ['CAPTURE_INTERFACE']
    capture.stop_capture()
    import time; time.sleep(0.3)
    capture.start_capture(use_scapy=use_real)
    return jsonify({
        'status': 'started',
        'mode': capture.get_mode(),
        'interface': capture.get_interface(),
        'local_ip': capture.get_local_ip()
    })

@app.route('/api/interfaces')
@login_required
def api_interfaces():
    return jsonify({
        'interfaces': capture.list_interfaces(),
        'current': capture.get_interface(),
        'local_ip': capture.get_local_ip(),
        'mode': capture.get_mode(),
        'is_render': config.IS_RENDER
    })

@app.route('/api/capture/stop', methods=['POST'])
@login_required
def api_capture_stop():
    capture.stop_capture(); return jsonify({'status': 'stopped'})


# ═══ PACKET MONITOR ════════════════════════════════
@app.route('/packets')
@login_required
def packets():
    page=int(request.args.get('page',1)); q=request.args.get('q','')
    proto=request.args.get('protocol',''); st=request.args.get('status','')
    rows,total=db.search_packets(q,proto,st,page,config.PACKETS_PER_PAGE)
    tp=max(1,(total+config.PACKETS_PER_PAGE-1)//config.PACKETS_PER_PAGE)
    proto_opts="".join(f'<option value="{p}" {"selected" if proto==p else ""}>{p}</option>'
                       for p in ['TCP','UDP','ICMP','HTTP','HTTPS','DNS','OTHER'])
    rows_html="".join(f"""<tr><td class="mono">{r['timestamp']}</td><td class="mono">{r['source_ip']}</td>
      <td class="mono">{r['destination_ip']}</td><td>{r['protocol']}</td>
      <td class="mono">{r['port']}</td><td class="mono">{r['packet_size']}B</td>
      <td><span class="badge {'bt' if r['status']=='threat' else 'bn'}">{r['status']}</span></td></tr>"""
      for r in rows) or '<tr><td colspan="7" class="empty">No packets found</td></tr>'
    prev_link=f'<a href="?page={page-1}&q={q}&protocol={proto}&status={st}">‹ Prev</a>' if page>1 else ''
    next_link=f'<a href="?page={page+1}&q={q}&protocol={proto}&status={st}">Next ›</a>' if page<tp else ''
    body=f"""<div class="ph"><div><h1 class="pt">Packet Monitor</h1><p class="ps">Search and filter captured packets</p></div></div>
    <div class="panel">
      <form method="GET" class="row g-2 align-items-end mb-3">
        <div class="col-md-4"><label class="fl">Search IP</label><input type="text" name="q" value="{q}" class="fc" placeholder="192.168.1.1"></div>
        <div class="col-md-3"><label class="fl">Protocol</label><select name="protocol" class="fc"><option value="">All</option>{proto_opts}</select></div>
        <div class="col-md-3"><label class="fl">Status</label><select name="status" class="fc"><option value="">All</option>
          <option value="normal" {"selected" if st=="normal" else ""}>Normal</option>
          <option value="threat" {"selected" if st=="threat" else ""}>Threat</option></select></div>
        <div class="col-md-2"><button type="submit" class="btn btn-p w-100"><i class="fa-solid fa-magnifying-glass"></i> Filter</button></div>
      </form>
      <div class="tw"><table class="tbl"><thead><tr><th>Time</th><th>Source</th><th>Dest</th><th>Protocol</th><th>Port</th><th>Size</th><th>Status</th></tr></thead>
      <tbody>{rows_html}</tbody></table></div>
      <div class="pages">{prev_link}<span class="cur">{page}/{tp}</span>{next_link}</div>
    </div>"""
    return _page('packets','Packet Monitor',body)


# ═══ THREATS & ALERTS ══════════════════════════════
@app.route('/alerts')
@login_required
def alerts():
    sev=request.args.get('severity','')
    conn=db.get_db()
    rows=conn.execute("SELECT * FROM threats WHERE severity=? ORDER BY time DESC LIMIT 200" if sev
                      else "SELECT * FROM threats ORDER BY time DESC LIMIT 200",
                      (sev,) if sev else ()).fetchall()
    conn.close()
    threats=[dict(r) for r in rows]
    sev_btns="".join(f'<a href="?severity={s}" class="btn btn-sm {"btn-p" if sev==s else "btn-o"}">{s or "All"}</a>'
                     for s in ['','Critical','High','Medium','Low'])
    sm={'Critical':'bc','High':'bh','Medium':'bm','Low':'bl'}
    dot_colors={'Critical':'var(--red)','High':'var(--orange)','Medium':'var(--yellow)','Low':'var(--green)'}
    rows_html="".join(f"""<tr id="row-{t['id']}">
      <td><span class="dot" style="background:{dot_colors.get(t['severity'],'var(--blue)')}"></span>
        <span class="badge {sm.get(t['severity'],'bn')}">{t['severity']}</span></td>
      <td><strong>{t['attack_name']}</strong></td>
      <td class="mono">{t['source_ip'] or '-'}</td><td>{t['protocol'] or '-'}</td>
      <td class="mono" style="font-size:12px">{(t['time'] or '')[:16]}</td>
      <td style="max-width:240px;font-size:12px;color:var(--txt2)">{t['recommendation'] or '-'}</td>
      <td><span id="st-{t['id']}" class="badge bn">{t['status']}</span></td>
      <td><div class="d-flex gap-1">
        <button class="btn btn-d btn-sm" onclick="act({t['id']},'block_ip')" title="Block"><i class="fa-solid fa-ban"></i></button>
        <button class="btn btn-o btn-sm" onclick="act({t['id']},'ignore')" title="Ignore"><i class="fa-solid fa-eye-slash"></i></button>
        <button class="btn btn-s btn-sm" onclick="act({t['id']},'resolve')" title="Resolved"><i class="fa-solid fa-check"></i></button>
      </div></td></tr>""" for t in threats) or '<tr><td colspan="8" class="empty">No threats detected yet</td></tr>'
    body=f"""<div class="ph"><div><h1 class="pt">Threats &amp; Alerts</h1><p class="ps">Review and act on detected threats</p></div>
      <div class="d-flex gap-2 flex-wrap">{sev_btns}</div></div>
    <div class="panel"><div class="tw"><table class="tbl">
      <thead><tr><th>Severity</th><th>Attack</th><th>Source IP</th><th>Protocol</th><th>Time</th><th>Recommendation</th><th>Status</th><th>Action</th></tr></thead>
      <tbody>{rows_html}</tbody></table></div></div>"""
    js="""<script>async function act(id,action){
      const r=await fetch(`/api/threat/${id}/action`,{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
      const d=await r.json();document.getElementById(`st-${id}`).textContent=d.new_status;
    }</script>"""
    return _page('alerts','Threats & Alerts',body,js)


@app.route('/api/threat/<int:tid>/action', methods=['POST'])
@login_required
def threat_action(tid):
    action=(request.json or {}).get('action','')
    status={'block_ip':'blocked','ignore':'ignored','resolve':'resolved'}.get(action,'open')
    conn=db.get_db(); conn.execute("UPDATE threats SET status=? WHERE id=?",(status,tid)); conn.commit(); conn.close()
    return jsonify({'status':'ok','new_status':status})


# ═══ REPORTS ═══════════════════════════════════════
@app.route('/reports')
@login_required
def reports_page():
    conn=db.get_db()
    history=[dict(h) for h in conn.execute("SELECT * FROM reports ORDER BY date DESC LIMIT 50").fetchall()]
    conn.close()
    hist_rows="".join(f'<tr><td class="mono">{h["report_name"]}</td><td class="mono">{h["date"]}</td><td>{h["total_attacks"]}</td></tr>'
                      for h in history) or '<tr><td colspan="3" class="empty">No reports yet</td></tr>'
    body=f"""<div class="ph"><div><h1 class="pt">Reports</h1><p class="ps">Generate and download security reports</p></div></div>
    <div class="g3">
      <div class="panel text-center">
        <div class="si" style="background:rgba(239,68,68,.15);color:var(--red);margin:0 auto 14px"><i class="fa-solid fa-file-pdf"></i></div>
        <h5 class="mb-2">PDF Report</h5><p style="font-size:12.5px;color:var(--txt2);margin-bottom:16px">Full report with threats, attack frequency and recommendations.</p>
        <a href="{url_for('generate_report',fmt='pdf')}" class="btn btn-p w-100 justify-content-center"><i class="fa-solid fa-download"></i> Generate PDF</a>
      </div>
      <div class="panel text-center">
        <div class="si" style="background:rgba(16,185,129,.15);color:var(--green);margin:0 auto 14px"><i class="fa-solid fa-file-csv"></i></div>
        <h5 class="mb-2">CSV Export</h5><p style="font-size:12.5px;color:var(--txt2);margin-bottom:16px">Raw threat data — open in Excel or Google Sheets.</p>
        <a href="{url_for('generate_report',fmt='csv')}" class="btn btn-o w-100 justify-content-center"><i class="fa-solid fa-download"></i> Generate CSV</a>
      </div>
      <div class="panel text-center">
        <div class="si" style="background:rgba(59,130,246,.15);color:var(--blue);margin:0 auto 14px"><i class="fa-solid fa-file-excel"></i></div>
        <h5 class="mb-2">Excel Report</h5><p style="font-size:12.5px;color:var(--txt2);margin-bottom:16px">Multi-sheet workbook with threats and statistics.</p>
        <a href="{url_for('generate_report',fmt='excel')}" class="btn btn-o w-100 justify-content-center"><i class="fa-solid fa-download"></i> Generate Excel</a>
      </div>
    </div>
    <div class="panel"><div class="ptitle">Report History</div>
      <div class="tw"><table class="tbl"><thead><tr><th>Filename</th><th>Generated</th><th>Total Attacks</th></tr></thead>
      <tbody>{hist_rows}</tbody></table></div></div>"""
    return _page('reports_page','Reports',body)


@app.route('/reports/generate/<fmt>')
@login_required
def generate_report(fmt):
    try:
        if fmt=='pdf':   fp,fn=rpt.generate_pdf()
        elif fmt=='csv': fp,fn=rpt.generate_csv()
        elif fmt=='excel': fp,fn=rpt.generate_excel()
        else: return jsonify({'error':'Unknown format'}),400
        return send_file(fp, as_attachment=True, download_name=fn)
    except Exception as e:
        print(f"[Report] {e}"); traceback.print_exc()
        _flash('error',f'Report error: {e}')
        return redirect(url_for('reports_page'))


# ═══ SETTINGS ══════════════════════════════════════
@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    if request.method=='POST':
        for key in ['port_scan_threshold','ping_flood_threshold','brute_force_threshold',
                    'large_packet_threshold','capture_interface','alert_email']:
            val=request.form.get(key)
            if val is not None: db.set_setting(key,val)
        db.set_setting('email_alerts','true' if request.form.get('email_alerts') else 'false')
        _flash('success','Settings saved.')
        return redirect(url_for('settings'))
    s={k:db.get_setting(k) for k in ['port_scan_threshold','ping_flood_threshold',
       'brute_force_threshold','large_packet_threshold','capture_interface','email_alerts','alert_email']}
    mi=ml_model.get_model_info()
    ml_sec=(f"<p style='font-size:13px;margin-bottom:6px'>Algorithm: <strong>{mi['algorithm'].replace('_',' ').title()}</strong></p>"
            f"<p style='font-size:13px;margin-bottom:16px'>Accuracy: <strong>{mi['accuracy']*100:.2f}%</strong></p>"
            if mi else "<p style='color:var(--muted);margin-bottom:16px'>Model training in progress…</p>")
    fields="".join(f"""<div class="fg"><label class="fl">{lbl}</label>
      <input type="{'number' if 'threshold' in k else 'text'}" name="{k}" value="{s.get(k,'')}" class="fc"></div>"""
      for k,lbl in [('port_scan_threshold','Port Scan Threshold (ports/min)'),
                    ('ping_flood_threshold','Ping Flood Threshold (packets/10s)'),
                    ('brute_force_threshold','Brute Force Threshold (attempts/min)'),
                    ('large_packet_threshold','Large Packet Threshold (bytes)'),
                    ('capture_interface','Capture Interface'),('alert_email','Alert Email')])
    body=f"""<div class="ph"><div><h1 class="pt">Settings</h1><p class="ps">Thresholds, ML model and account</p></div></div>
    <div class="g2">
      <div class="panel"><div class="ptitle">Detection Thresholds</div>
        <form method="POST" action="{url_for('settings')}">{fields}
          <div class="fg"><label class="d-flex align-items-center gap-2" style="font-size:13px;color:var(--txt2)">
            <input type="checkbox" name="email_alerts" {'checked' if s.get('email_alerts')=='true' else ''}> Enable Email Alerts
          </label></div>
          <button type="submit" class="btn btn-p"><i class="fa-solid fa-floppy-disk"></i> Save</button>
        </form></div>
      <div>
        <div class="panel"><div class="ptitle">Machine Learning Model</div>{ml_sec}
          <form method="POST" action="{url_for('train_model_route')}">
            <div class="fg"><label class="fl">Algorithm</label>
              <select name="algorithm" class="fc">
                <option value="random_forest">Random Forest</option>
                <option value="decision_tree">Decision Tree</option>
                <option value="knn">K-Nearest Neighbors</option>
                <option value="logistic_regression">Logistic Regression</option>
              </select></div>
            <button type="submit" class="btn btn-o w-100 justify-content-center">
              <i class="fa-solid fa-brain"></i> Train / Retrain Model</button>
          </form></div>
        <div class="panel"><div class="ptitle">Change Password</div>
          <form method="POST" action="{url_for('change_password')}">
            <div class="fg"><label class="fl">Current Password</label><input type="password" name="old_password" class="fc" required></div>
            <div class="fg"><label class="fl">New Password</label><input type="password" name="new_password" class="fc" required></div>
            <button type="submit" class="btn btn-o w-100 justify-content-center">
              <i class="fa-solid fa-key"></i> Update Password</button>
          </form></div>
      </div></div>"""
    return _page('settings','Settings',body)


@app.route('/settings/train', methods=['POST'])
@login_required
def train_model_route():
    algo=request.form.get('algorithm','random_forest')
    try:
        acc=ml_model.train_model(algo); _flash('success',f'Model trained! Accuracy: {acc:.2%}')
    except Exception as e: _flash('error',f'Training failed: {e}')
    return redirect(url_for('settings'))


@app.route('/settings/change_password', methods=['POST'])
@login_required
def change_password():
    old=request.form.get('old_password',''); new=request.form.get('new_password','')
    conn=db.get_db(); user=conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    if user and user['password']==hashlib.sha256(old.encode()).hexdigest():
        conn.execute("UPDATE users SET password=? WHERE id=?",(hashlib.sha256(new.encode()).hexdigest(),session['user_id']))
        conn.commit(); _flash('success','Password changed.')
    else: _flash('error','Old password incorrect.')
    conn.close(); return redirect(url_for('settings'))


# ═══ LOGS VIEWER ═══════════════════════════════════
@app.route('/logs')
@login_required
def logs_viewer():
    lt=request.args.get('type','packets')
    if lt=='threats': data=db.get_recent_threats(200)
    elif lt=='alerts': data=db.get_recent_alerts(200)
    else: data=db.get_recent_packets(200)
    tab_btns="".join(f'<a href="?type={t}" class="btn btn-sm {"btn-p" if lt==t else "btn-o"}">{t.title()}</a>'
                     for t in ['packets','threats','alerts'])
    sm={'Critical':'bc','High':'bh','Medium':'bm','Low':'bl'}
    if lt=='packets':
        hdrs="<tr><th>Time</th><th>Source</th><th>Dest</th><th>Protocol</th><th>Size</th><th>Status</th></tr>"
        rows="".join(f'<tr><td class="mono">{d["timestamp"]}</td><td class="mono">{d["source_ip"]}</td>'
                     f'<td class="mono">{d["destination_ip"]}</td><td>{d["protocol"]}</td>'
                     f'<td class="mono">{d["packet_size"]}B</td>'
                     f'<td><span class="badge {"bt" if d["status"]=="threat" else "bn"}">{d["status"]}</span></td></tr>'
                     for d in data) or '<tr><td colspan="6" class="empty">No logs</td></tr>'
    elif lt=='threats':
        hdrs="<tr><th>Attack</th><th>Severity</th><th>Source IP</th><th>Time</th><th>Status</th></tr>"
        rows="".join(f'<tr><td>{d["attack_name"]}</td>'
                     f'<td><span class="badge {sm.get(d["severity"],"bn")}">{d["severity"]}</span></td>'
                     f'<td class="mono">{d["source_ip"]}</td><td class="mono">{d["time"]}</td><td>{d["status"]}</td></tr>'
                     for d in data) or '<tr><td colspan="5" class="empty">No logs</td></tr>'
    else:
        hdrs="<tr><th>Message</th><th>Severity</th><th>Source IP</th><th>Time</th></tr>"
        rows="".join(f'<tr><td>{d["message"]}</td>'
                     f'<td><span class="badge {sm.get(d["severity"],"bn")}">{d["severity"]}</span></td>'
                     f'<td class="mono">{d["source_ip"]}</td><td class="mono">{d["time"]}</td></tr>'
                     for d in data) or '<tr><td colspan="4" class="empty">No logs</td></tr>'
    body=f"""<div class="ph"><div><h1 class="pt">Logs Viewer</h1><p class="ps">Browse system logs</p></div>
      <div class="d-flex gap-2">{tab_btns}</div></div>
    <div class="panel"><div class="tw"><table class="tbl"><thead>{hdrs}</thead><tbody>{rows}</tbody></table></div></div>"""
    return _page('logs_viewer','Logs Viewer',body)


# ═══ ML PREDICT API ════════════════════════════════
@app.route('/api/predict', methods=['POST'])
@login_required
def api_predict():
    d=request.json or {}
    label,conf=ml_model.predict(protocol=d.get('protocol','TCP'),packet_size=int(d.get('packet_size',500)),
                                 port=int(d.get('port',80)),ttl=int(d.get('ttl',64)),flags=d.get('flags',''))
    return jsonify({'prediction':label,'confidence':round(conf,3)})


# ═══ ERROR HANDLERS ════════════════════════════════
_ERR = lambda code, emoji, title, msg: (
    f"<!DOCTYPE html><html><head><title>{code}</title>"
    f"<style>body{{background:#0b0f1a;color:#e8ecf4;font-family:Inter,sans-serif;"
    f"display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}"
    f".b{{background:#151c2c;border:1px solid #232c42;border-radius:16px;padding:40px;"
    f"width:380px;text-align:center}}h1{{font-size:20px;font-weight:800;margin:16px 0 8px}}"
    f"p{{color:#8b94ab;font-size:13.5px;margin-bottom:24px}}"
    f"a{{display:block;background:#3b82f6;color:#fff;padding:10px;border-radius:8px;"
    f"text-decoration:none;font-weight:600}}</style></head>"
    f"<body><div class='b'><div style='font-size:48px'>{emoji}</div>"
    f"<h1>{title}</h1><p>{msg}</p><a href='/'>Back to Dashboard</a></div></body></html>", code)

@app.errorhandler(404)
def not_found(e): return _ERR(404,'🔍','404 — Not Found',"The page doesn't exist.")

@app.errorhandler(500)
def server_error(e): print(f"[500] {e}"); traceback.print_exc(); return _ERR(500,'⚠️','500 — Server Error','Please try again.')


# ═══ ENTRY POINT ═══════════════════════════════════
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=config.DEBUG)
