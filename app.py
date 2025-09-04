import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, Response
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import pandas as pd

from config import Config
from models import db, User, Campaign, EmailLog
from security import encrypt_text, decrypt_text
from mailer import send_bulk

load_dotenv()

login_manager = LoginManager()
login_manager.login_view = 'login'


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    Config.init_app(app)
    app.decrypt = decrypt_text

    db.init_app(app)
    login_manager.init_app(app)

    # Register user loader
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------- ROUTES ----------

    @app.route('/')
    def home():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    # --- Auth ---
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            password = request.form['password']
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Invalid credentials', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    # --- Admin utilities ---
    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
                flash('Admin access required', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapper

    @app.route('/admin/users', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def admin_users():
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'create':
                email = request.form['email'].strip().lower()
                password = request.form['password']
                is_admin = bool(request.form.get('is_admin'))
                if User.query.filter_by(email=email).first():
                    flash('Email already exists', 'danger')
                else:
                    u = User(email=email, password_hash=generate_password_hash(password), is_admin=is_admin)
                    db.session.add(u)
                    db.session.commit()
                    flash('User created', 'success')
            elif action == 'reset':
                uid = int(request.form['user_id'])
                password = request.form['password']
                u = User.query.get(uid)
                if u:
                    u.password_hash = generate_password_hash(password)
                    db.session.commit()
                    flash('Password reset', 'success')
            elif action == 'delete':
                uid = int(request.form['user_id'])
                if uid == current_user.id:
                    flash('Cannot delete the currently logged-in admin', 'danger')
                else:
                    u = User.query.get(uid)
                    if u:
                        db.session.delete(u)
                        db.session.commit()
                        flash('User deleted', 'success')
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template('admin_users.html', users=users)

    # --- Settings ---
    @app.route('/settings', methods=['POST'])
    @login_required
    def settings():
        cu = current_user
        cu.smtp_host = request.form.get('smtp_host')
        cu.smtp_port = int(request.form.get('smtp_port', '587'))
        cu.smtp_user = request.form.get('smtp_user')
        smtp_pass = request.form.get('smtp_pass')
        if smtp_pass:
            cu.smtp_pass_enc = encrypt_text(smtp_pass)
        cu.rate_per_minute = int(request.form.get('rate_per_minute', '60'))
        cu.from_name = request.form.get('from_name')
        cu.from_email = request.form.get('from_email')
        db.session.commit()
        flash('Settings saved', 'success')
        return redirect(url_for('dashboard'))

    # --- Dashboard / New Campaign ---
    @app.route('/dashboard', methods=['GET', 'POST'])
    @login_required
    def dashboard():
        if request.method == 'POST':
            subject = request.form['subject']
            name = request.form.get('name') or subject
            html_file = request.files.get('html_file')
            html_text = request.form.get('html_text')
            if html_file and html_file.filename:
                html_body = html_file.read().decode('utf-8', errors='ignore')
            else:
                html_body = html_text or ''
            attachment = request.files.get('attachment')
            attachment_path = None
            if attachment and attachment.filename:
                fname = secure_filename(attachment.filename)
                attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                attachment.save(attachment_path)
            rec_file = request.files.get('recipients')
            if not rec_file or not rec_file.filename:
                flash('Please upload recipients file', 'danger')
                return redirect(url_for('dashboard'))
            ext = os.path.splitext(rec_file.filename)[1].lower()
            if ext in ['.xls', '.xlsx']:
                df = pd.read_excel(rec_file)
            else:
                df = pd.read_csv(rec_file)
            if 'email' not in df.columns:
                flash("Recipients file must have column named 'email'", 'danger')
                return redirect(url_for('dashboard'))
            df.columns = [str(c).strip() for c in df.columns]
            rows = []
            for _, r in df.iterrows():
                row = {str(k): ('' if pd.isna(v) else str(v)) for k, v in r.to_dict().items()}
                email = row.get('email', '').strip()
                if email:
                    rows.append(row)
            if not rows:
                flash('No valid recipients found', 'danger')
                return redirect(url_for('dashboard'))
            camp = Campaign(user_id=current_user.id, name=name, subject=subject, html_body=html_body, attachment_path=attachment_path)
            db.session.add(camp)
            db.session.commit()
            base_url = app.config['APP_BASE_URL']
            sent, failed = send_bulk(app, current_user, camp, rows, base_url, current_user.rate_per_minute)
            return render_template('send_result.html', sent=sent, failed=failed, total=len(rows), camp=camp)

        camps = Campaign.query.filter_by(user_id=current_user.id).order_by(Campaign.created_at.desc()).all()
        return render_template('dashboard.html', user=current_user, camps=camps)

    # --- Campaigns ---
    @app.route('/campaigns')
    @login_required
    def campaign_list():
        camps = Campaign.query.filter_by(user_id=current_user.id).order_by(Campaign.created_at.desc()).all()
        stats = {}
        for c in camps:
            q = EmailLog.query.filter_by(campaign_id=c.id)
            stats[c.id] = {
                'total': q.count(),
                'sent': q.filter_by(status='sent').count(),
                'failed': q.filter_by(status='failed').count(),
                'opened': q.filter(EmailLog.opened_at.isnot(None)).count(),
                'clicks': sum(e.clicks for e in q.all()),
            }
        return render_template('campaign_list.html', camps=camps, stats=stats)

    @app.route('/campaigns/<int:cid>')
    @login_required
    def campaign_detail(cid):
        camp = Campaign.query.filter_by(id=cid, user_id=current_user.id).first_or_404()
        logs = EmailLog.query.filter_by(campaign_id=camp.id).order_by(EmailLog.id.desc()).all()
        return render_template('campaign_detail.html', camp=camp, logs=logs)

    # --- Tracking ---
    @app.route('/o/<token>')
    def track_open(token):
        log = EmailLog.query.filter_by(token=token).first()
        if log and not log.opened_at:
            log.opened_at = datetime.utcnow()
            db.session.commit()
        pixel = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        return Response(pixel, mimetype='image/gif')

    @app.route('/r/<token>')
    def track_click(token):
        url = request.args.get('u')
        if not url:
            return redirect(url_for('home'))
        log = EmailLog.query.filter_by(token=token).first()
        if log:
            log.clicks = (log.clicks or 0) + 1
            db.session.commit()
        return redirect(url)

    @app.route('/uploads/<path:filename>')
    @login_required
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # Ensure DB
    @app.before_request
    def ensure_db():
        if not getattr(app, "_db_initialized", False):
            db.create_all()
            app._db_initialized = True

    return app


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
