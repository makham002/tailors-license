"""
Tailors License Server
Deploy on Render.com (free tier) or Railway.app

Environment variables:
  ADMIN_PASSWORD  — password for the admin panel (default: change_me)
  SECRET_KEY      — Flask secret key (set any random string)
"""

import os
import sqlite3
import secrets
import string
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tailors-secret-2024-change-this')

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change_me')
DB_FILE = 'licenses.db'

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key         TEXT UNIQUE NOT NULL,
                type        TEXT NOT NULL,          -- monthly / lifetime
                shop_name   TEXT NOT NULL,
                hardware_id TEXT DEFAULT NULL,       -- set on first activation
                is_active   INTEGER DEFAULT 1,
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT DEFAULT NULL,       -- NULL = lifetime
                months      INTEGER DEFAULT 1
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS activations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key         TEXT NOT NULL,
                hardware_id TEXT NOT NULL,
                action      TEXT NOT NULL,           -- activate / verify
                timestamp   TEXT DEFAULT (datetime('now')),
                app_version TEXT DEFAULT ''
            )
        ''')
        db.commit()

init_db()

# ─── KEY GENERATION ──────────────────────────────────────────────────────────

def gen_key(key_type):
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(secrets.choice(chars) for _ in range(8))
    prefix = 'TM' if key_type == 'monthly' else 'TL'
    return f'{prefix}-{suffix}'

# ─── API ─────────────────────────────────────────────────────────────────────

@app.route('/api/activate', methods=['POST'])
def api_activate():
    data = request.get_json(silent=True) or {}
    key         = (data.get('key') or '').strip().upper()
    hardware_id = (data.get('hardware_id') or '').strip()
    app_version = (data.get('app_version') or '').strip()

    if not key or not hardware_id:
        return jsonify(success=False, message='Missing key or hardware_id'), 400

    with get_db() as db:
        row = db.execute('SELECT * FROM licenses WHERE key=?', [key]).fetchone()

        if not row:
            return jsonify(success=False, message='Invalid license key. Please check and try again.')

        if not row['is_active']:
            return jsonify(success=False, message='This license key has been deactivated. Please contact support.')

        # Check expiry for monthly
        if row['type'] == 'monthly' and row['expires_at']:
            if datetime.utcnow() > datetime.fromisoformat(row['expires_at']):
                return jsonify(success=False, message='This license key has expired. Please renew.')

        # Already bound to a different hardware
        if row['hardware_id'] and row['hardware_id'] != hardware_id:
            return jsonify(
                success=False,
                message='This key is already activated on another computer.\n'
                        'Contact support on WhatsApp if you need to transfer it.'
            )

        # Bind hardware if first activation
        if not row['hardware_id']:
            db.execute('UPDATE licenses SET hardware_id=? WHERE key=?', [hardware_id, key])

        # Log activation
        db.execute('INSERT INTO activations (key, hardware_id, action, app_version) VALUES (?,?,?,?)',
                   [key, hardware_id, 'activate', app_version])
        db.commit()

    return jsonify(
        success=True,
        type=row['type'],
        shop_name=row['shop_name'],
        expiry=row['expires_at']
    )


@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.get_json(silent=True) or {}
    key         = (data.get('key') or '').strip().upper()
    hardware_id = (data.get('hardware_id') or '').strip()

    if not key or not hardware_id:
        return jsonify(valid=False, message='Missing parameters'), 400

    with get_db() as db:
        row = db.execute('SELECT * FROM licenses WHERE key=?', [key]).fetchone()

        if not row:
            return jsonify(valid=False, message='Key not found')

        if not row['is_active']:
            return jsonify(valid=False, message='License has been deactivated')

        if row['hardware_id'] and row['hardware_id'] != hardware_id:
            return jsonify(valid=False, message='Hardware mismatch')

        days_remaining = None
        if row['type'] == 'monthly' and row['expires_at']:
            delta = datetime.fromisoformat(row['expires_at']) - datetime.utcnow()
            days_remaining = max(0, delta.days)
            if days_remaining == 0 and delta.total_seconds() <= 0:
                return jsonify(valid=False, message='License expired')

        db.execute('INSERT INTO activations (key, hardware_id, action) VALUES (?,?,?)',
                   [key, hardware_id, 'verify'])
        db.commit()

    return jsonify(
        valid=True,
        type=row['type'],
        shop_name=row['shop_name'],
        expiry=row['expires_at'],
        days_remaining=days_remaining
    )


# ─── ADMIN AUTH ───────────────────────────────────────────────────────────────

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = ''
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin')
        error = 'Wrong password.'

    return render_template_string(LOGIN_HTML, error=error)


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')


# ─── ADMIN PANEL ─────────────────────────────────────────────────────────────

@app.route('/admin')
@require_login
def admin_index():
    with get_db() as db:
        keys = db.execute(
            'SELECT * FROM licenses ORDER BY created_at DESC'
        ).fetchall()
        total = len(keys)
        active = sum(1 for k in keys if k['is_active'])
    return render_template_string(ADMIN_HTML, keys=keys, total=total, active=active)


@app.route('/admin/generate', methods=['POST'])
@require_login
def admin_generate():
    key_type  = request.form.get('type', 'monthly')
    shop_name = request.form.get('shop_name', 'Unknown Shop').strip()
    months    = int(request.form.get('months', 1))

    new_key = gen_key(key_type)

    if key_type == 'monthly':
        expires_at = (datetime.utcnow() + timedelta(days=30 * months)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        expires_at = None

    with get_db() as db:
        db.execute(
            'INSERT INTO licenses (key, type, shop_name, expires_at, months) VALUES (?,?,?,?,?)',
            [new_key, key_type, shop_name, expires_at, months]
        )
        db.commit()

    return redirect('/admin')


@app.route('/admin/toggle/<key>')
@require_login
def admin_toggle(key):
    with get_db() as db:
        row = db.execute('SELECT is_active FROM licenses WHERE key=?', [key]).fetchone()
        if row:
            db.execute('UPDATE licenses SET is_active=? WHERE key=?', [1 - row['is_active'], key])
            db.commit()
    return redirect('/admin')


@app.route('/admin/extend/<key>', methods=['POST'])
@require_login
def admin_extend(key):
    extra_months = int(request.form.get('months', 1))
    with get_db() as db:
        row = db.execute('SELECT * FROM licenses WHERE key=?', [key]).fetchone()
        if row and row['type'] == 'monthly':
            current = datetime.fromisoformat(row['expires_at']) if row['expires_at'] else datetime.utcnow()
            new_exp = (current + timedelta(days=30 * extra_months)).strftime('%Y-%m-%d %H:%M:%S')
            db.execute('UPDATE licenses SET expires_at=? WHERE key=?', [new_exp, key])
            db.commit()
    return redirect('/admin')


@app.route('/admin/reset/<key>')
@require_login
def admin_reset_hardware(key):
    with get_db() as db:
        db.execute('UPDATE licenses SET hardware_id=NULL WHERE key=?', [key])
        db.commit()
    return redirect('/admin')


# ─── HTML TEMPLATES ───────────────────────────────────────────────────────────

LOGIN_HTML = '''<!DOCTYPE html>
<html><head><title>Tailors Admin Login</title>
<style>
  body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#1E293B;margin:0}
  .box{background:#fff;padding:36px;border-radius:12px;width:340px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
  h2{margin:0 0 20px;text-align:center;color:#1E293B}
  input{width:100%;padding:10px;border:1.5px solid #E2E8F0;border-radius:6px;font-size:14px;box-sizing:border-box;margin-bottom:12px}
  button{width:100%;padding:11px;background:#2563EB;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
  .err{background:#FEE2E2;color:#991B1B;padding:8px 12px;border-radius:6px;font-size:13px;margin-bottom:12px}
</style></head>
<body><div class="box">
  <h2>✂ Tailors Admin</h2>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post">
    <input type="password" name="password" placeholder="Admin Password" autofocus>
    <button type="submit">Login</button>
  </form>
</div></body></html>'''


ADMIN_HTML = '''<!DOCTYPE html>
<html><head><title>Tailors Admin</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui;background:#F1F5F9;color:#1E293B}
  .topbar{background:#1E293B;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
  .topbar h1{font-size:18px}
  .topbar a{color:#94A3B8;text-decoration:none;font-size:13px}
  .wrap{max-width:1100px;margin:0 auto;padding:24px}
  .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
  .stat{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  .stat-label{font-size:12px;color:#64748B;text-transform:uppercase;font-weight:600}
  .stat-val{font-size:28px;font-weight:800;color:#2563EB;margin-top:4px}
  .card{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}
  h2{font-size:15px;font-weight:700;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid #E2E8F0}
  .form-row{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:10px;align-items:end}
  input,select{padding:8px 10px;border:1.5px solid #E2E8F0;border-radius:6px;font-size:13px;width:100%}
  .btn{padding:8px 14px;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap}
  .btn-blue{background:#2563EB;color:#fff}
  .btn-red{background:#EF4444;color:#fff}
  .btn-green{background:#10B981;color:#fff}
  .btn-gray{background:#E2E8F0;color:#1E293B}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;padding:9px 12px;background:#F8FAFC;color:#64748B;font-size:11px;text-transform:uppercase;font-weight:700;border-bottom:1px solid #E2E8F0}
  td{padding:10px 12px;border-bottom:1px solid #F1F5F9;vertical-align:middle}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
  .badge-m{background:#DBEAFE;color:#1E40AF}
  .badge-l{background:#DCFCE7;color:#166534}
  .badge-off{background:#FEE2E2;color:#991B1B}
  code{background:#F1F5F9;padding:1px 6px;border-radius:4px;font-size:12px;letter-spacing:1px}
  .actions{display:flex;gap:6px}
  .ext-form{display:inline-flex;gap:4px;align-items:center}
</style></head>
<body>
<div class="topbar">
  <h1>✂ Tailors License Admin</h1>
  <a href="/admin/logout">Logout</a>
</div>
<div class="wrap">

  <div class="stats">
    <div class="stat"><div class="stat-label">Total Keys</div><div class="stat-val">{{ total }}</div></div>
    <div class="stat"><div class="stat-label">Active Keys</div><div class="stat-val">{{ active }}</div></div>
    <div class="stat"><div class="stat-label">Inactive</div><div class="stat-val">{{ total - active }}</div></div>
  </div>

  <div class="card">
    <h2>Generate New License Key</h2>
    <form method="post" action="/admin/generate">
      <div class="form-row">
        <div>
          <label style="font-size:12px;font-weight:600;color:#64748B">Shop Name</label>
          <input name="shop_name" placeholder="e.g. Fashion Tailors Lahore" required>
        </div>
        <div>
          <label style="font-size:12px;font-weight:600;color:#64748B">Type</label>
          <select name="type">
            <option value="monthly">Monthly (Rs 500)</option>
            <option value="lifetime">Lifetime (Rs 15,000)</option>
          </select>
        </div>
        <div>
          <label style="font-size:12px;font-weight:600;color:#64748B">Months (monthly only)</label>
          <input name="months" type="number" value="1" min="1" max="24">
        </div>
        <div>
          <label style="font-size:12px;font-weight:600;color:#64748B">&nbsp;</label>
          <button type="submit" class="btn btn-blue" style="width:100%">Generate Key</button>
        </div>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>All License Keys</h2>
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>Type</th>
          <th>Shop Name</th>
          <th>Expiry</th>
          <th>Hardware ID</th>
          <th>Status</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
      {% for k in keys %}
        <tr>
          <td><code>{{ k['key'] }}</code></td>
          <td>
            {% if k['type'] == 'monthly' %}
              <span class="badge badge-m">Monthly</span>
            {% else %}
              <span class="badge badge-l">Lifetime</span>
            {% endif %}
          </td>
          <td>{{ k['shop_name'] }}</td>
          <td>{{ k['expires_at'] or '—' }}</td>
          <td style="font-size:11px;color:#94A3B8">{{ k['hardware_id'] or 'Not activated' }}</td>
          <td>
            {% if k['is_active'] %}
              <span class="badge badge-l">Active</span>
            {% else %}
              <span class="badge badge-off">Disabled</span>
            {% endif %}
          </td>
          <td style="color:#94A3B8;font-size:12px">{{ k['created_at'][:10] }}</td>
          <td>
            <div class="actions">
              <a href="/admin/toggle/{{ k['key'] }}" class="btn {% if k['is_active'] %}btn-red{% else %}btn-green{% endif %}">
                {% if k['is_active'] %}Disable{% else %}Enable{% endif %}
              </a>
              {% if k['type'] == 'monthly' %}
              <form class="ext-form" method="post" action="/admin/extend/{{ k['key'] }}">
                <input type="number" name="months" value="1" min="1" max="12" style="width:50px">
                <button class="btn btn-gray" type="submit">+mo</button>
              </form>
              {% endif %}
              <a href="/admin/reset/{{ k['key'] }}" class="btn btn-gray"
                 onclick="return confirm('Reset hardware binding for this key?')">Reset HW</a>
            </div>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div></body></html>'''


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
