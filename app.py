# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import os
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import click
from flask.cli import with_appcontext
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)

# Configuration

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    "DATABASE_URL", "sqlite:///users.db"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
app.config['MAIL_USE_SSL'] = False

app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

# Zapier
ZAPIER_WEBHOOK_URL = os.getenv("ZAPIER_WEBHOOK_URL")

with open("static/countries_states.json", "r", encoding="utf-8") as f:
    WORLD_DATA = json.load(f)



db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.email}>'

# Registration Request Model
class RegistrationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<RegistrationRequest {self.email}>'
    
@click.command("create-superuser")
@click.option("--email", prompt=True)
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@with_appcontext
def create_superuser(email, username, password):
    if User.query.filter_by(email=email).first():
        click.echo("❌ User already exists")
        return

    user = User(
        email=email,
        username=username,
        password=generate_password_hash(password),
        is_admin=True,
        is_active=True
    )

    db.session.add(user)
    db.session.commit()

    click.echo("✅ Superuser created successfully")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_panel'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))




@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        reason = request.form.get('reason')
        
        # Validation
        if not email or not reason:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        # Check if email already has a pending request
        existing_request = RegistrationRequest.query.filter_by(email=email).first()
        if existing_request:
            if existing_request.status == 'pending':
                flash('You already have a pending registration request!', 'error')
            elif existing_request.status == 'rejected':
                flash('Your previous registration request was rejected. Please contact admin.', 'error')
            else:
                flash('This email is already registered!', 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('This email is already registered!', 'error')
            return redirect(url_for('register'))
        
        # Create registration request
        new_request = RegistrationRequest(email=email, reason=reason)
        
        try:
            db.session.add(new_request)
            db.session.commit()
            flash('Registration request submitted successfully! You will receive an email once approved.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        if not email or not password:
            flash('Please fill in all fields!', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Account not found. Please register first.', 'error')
            return redirect(url_for('login'))
        
        if not user.password:
            flash('Please set your password using the link sent to your email.', 'error')
            return redirect(url_for('login'))
        
        if not user.is_active:
            flash('Your account has been deactivated. Please contact admin.', 'error')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        
        if user.is_admin:
            return redirect(url_for('admin_panel'))
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/set-password/<token>', methods=['GET', 'POST'])
def set_password(token):
    try:
        email = serializer.loads(token, salt='password-setup', max_age=86400)  # 24 hours
    except:
        flash('Invalid or expired link!', 'error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('All fields are required!', 'error')
            return render_template('set_password.html', email=email)
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('set_password.html', email=email)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('set_password.html', email=email)
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists! Please choose another.', 'error')
            return render_template('set_password.html', email=email)
        
        # Set username and password
        user.username = username
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            db.session.commit()
            flash('Password set successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return render_template('set_password.html', email=email)
    
    return render_template('set_password.html', email=email)

@app.route('/admin-panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied! Admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    pending_requests = RegistrationRequest.query.filter_by(status='pending').order_by(RegistrationRequest.created_at.desc()).all()
    approved_requests = RegistrationRequest.query.filter_by(status='approved').order_by(RegistrationRequest.reviewed_at.desc()).limit(10).all()
    rejected_requests = RegistrationRequest.query.filter_by(status='rejected').order_by(RegistrationRequest.reviewed_at.desc()).limit(10).all()
    
    return render_template('admin_panel.html', 
                         username=current_user.username,
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests)

@app.route('/admin/approve-request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
    if reg_request.status != 'pending':
        return jsonify({'success': False, 'error': 'Request already processed'}), 400
    
    # Update request status
    reg_request.status = 'approved'
    reg_request.reviewed_at = datetime.utcnow()
    reg_request.reviewed_by = current_user.id
    
    # Create user account (without password)
    new_user = User(email=reg_request.email, username=None, password=None)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Generate password setup token
        token = serializer.dumps(reg_request.email, salt='password-setup')
        setup_link = url_for('set_password', token=token, _external=True)
        
        # Send email
        send_approval_email(reg_request.email, setup_link)
        
        flash(f'Request approved and email sent to {reg_request.email}', 'success')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/reject-request/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    reg_request = RegistrationRequest.query.get_or_404(request_id)
    
    if reg_request.status != 'pending':
        return jsonify({'success': False, 'error': 'Request already processed'}), 400
    
    # Update request status
    reg_request.status = 'rejected'
    reg_request.reviewed_at = datetime.utcnow()
    reg_request.reviewed_by = current_user.id
    
    try:
        db.session.commit()
        flash(f'Request from {reg_request.email} rejected', 'success')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

def send_approval_email(email, setup_link):
    """Send approval email with password setup link"""
    try:
        msg = Message(
            'Registration Approved - Set Your Password',
            recipients=[email]
        )
        msg.html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #667eea;">Welcome to SmartLead AI! 🎉</h2>
                    <p>Great news! Your registration request has been approved.</p>
                    <p>Please click the button below to set your password and complete your account setup:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{setup_link}" 
                           style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                  color: white;
                                  padding: 14px 30px;
                                  text-decoration: none;
                                  border-radius: 10px;
                                  display: inline-block;
                                  font-weight: 600;">
                            Set Your Password
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        This link will expire in 24 hours. If you didn't request this, please ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="color: #999; font-size: 12px;">
                        If the button doesn't work, copy and paste this link into your browser:<br>
                        <a href="{setup_link}" style="color: #667eea;">{setup_link}</a>
                    </p>
                </div>
            </body>
        </html>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Please enter your email!', 'error')
            return redirect(url_for('forgot_password'))
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            flash('Password reset instructions sent to your email!', 'success')
        else:
            flash('If that email exists, password reset instructions have been sent!', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_panel'))
    return render_template('dashboard.html', username=current_user.username)

@app.route('/generate-leads')
@login_required
def generate_leads():
    return render_template('generate_leads.html', username=current_user.username)

@app.route('/lead-platforms')
@login_required
def lead_platforms():
    return render_template('lead_platforms.html', username=current_user.username)

@app.route("/api/countries")
def api_countries():
    countries = sorted([c["name"] for c in WORLD_DATA])
    return jsonify(countries)

@app.route("/api/states")
def api_states():
    country = request.args.get("country")
    if not country:
        return jsonify([])

    for c in WORLD_DATA:
        if c["name"].lower() == country.lower():
            states = [s["name"] for s in c.get("states", [])]
            capital = c.get("capital")
            if capital and capital not in states:
                states.append(capital)
            states = sorted(states)
            return jsonify(states)

    return jsonify([])

@app.route('/submit-lead-request', methods=['POST'])
@login_required
def submit_lead_request():
    try:
        data = request.get_json()
        lead_type = data.get("leadType")
        country = data.get("country")
        states = data.get("states", [])
        quantity = data.get("quantity")
        platforms = data.get("platforms", [])

        location = f"{', '.join(states)} ({country})" if states else country

        payload = {
            "lead_type": lead_type,
            "location": location,
            "quantity": quantity,
            "platforms": ", ".join(platforms)
        }

        res = requests.post(ZAPIER_WEBHOOK_URL, json=payload)

        if res.status_code == 200:
            return jsonify({"success": True, "message": "Data sent successfully to Zapier"})
        else:
            return jsonify({"success": False, "error": f"Zapier returned {res.status_code}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('login'))


app.cli.add_command(create_superuser)

if __name__ == '__main__':
    app.run(debug=True)