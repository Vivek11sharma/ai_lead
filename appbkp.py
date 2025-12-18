# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import os

app = Flask(__name__)

# 🔗 Replace with your actual Zapier webhook URL
ZAPIER_WEBHOOK_URL = "https://hooks.zapier.com/hooks/catch/7358228/ui7ak92/"
# ZAPIER_WEBHOOK_URL = "https://hooks.zapier.com/hooks/catch/7358228/usjuqmc/"


# Load countries & states JSON once
with open("static/countries_states.json", "r", encoding="utf-8") as f:
    WORLD_DATA = json.load(f)

app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
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
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

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
            # In production, send actual reset email here
            # For demo purposes, we'll just show a success message
            flash('Password reset instructions sent to your email!', 'success')
        else:
            # Don't reveal if email exists or not (security best practice)
            flash('If that email exists, password reset instructions have been sent!', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@app.route('/generate-leads')
@login_required
def generate_leads():
    return render_template('generate_leads.html', username=current_user.username)

@app.route('/lead-platforms')
@login_required
def lead_platforms():
    return render_template('lead_platforms.html', username=current_user.username)

# API endpoints for countries and states

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

            # Extract states normally
            states = [s["name"] for s in c.get("states", [])]

            # Add country capital (if exists and not duplicate)
            capital = c.get("capital")
            if capital and capital not in states:
                states.append(capital)

            # Sort the list
            states = sorted(states)

            return jsonify(states)

    return jsonify([])



# @app.route("/api/countries")
# def get_countries():
#     try:
#         api_url = "https://api.first.org/data/v1/countries"
#         res = requests.get(api_url, timeout=10)
#         res.raise_for_status()
#         data = res.json()
#         countries = sorted([item["country"] for item in data["data"].values()])
#         return jsonify(countries)
#     except Exception as e:
#         print("Countries API Error:", e)
#         return jsonify({"error": str(e)}), 500


# @app.route("/api/states")
# def get_states():
#     """Fetch states for a given country from CountriesNow API."""
#     country = request.args.get("country")
#     if not country:
#         return jsonify([])

#     try:
#         api_url = "https://countriesnow.space/api/v0.1/countries/states"
#         payload = {"country": country}  # POST body
#         res = requests.post(api_url, json=payload, timeout=10)  # GET → POST fix
#         res.raise_for_status()
#         data = res.json()

#         # States mil jayenge yahan se
#         states = [state["name"] for state in data["data"]["states"]]
#         return jsonify(states)

#     except Exception as e:
#         print("States API Error:", e)
#         return jsonify({"error": str(e)}), 500


@app.route('/submit-lead-request', methods=['POST'])
@login_required
def submit_lead_request():
    """Handle lead generation form submission."""
    try:
        data = request.get_json()
        lead_type = data.get("leadType")
        country = data.get("country")
        states = data.get("states", [])
        quantity = data.get("quantity")
        platforms = data.get("platforms", [])

        # Make location string like: "California, Texas (USA)"
        location = f"{', '.join(states)} ({country})" if states else country

        # Payload to Zapier
        payload = {
            "lead_type": lead_type,
            "location": location,
            "quantity": quantity,
            "platforms": ", ".join(platforms)
        }

         # Send to Zapier
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

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)