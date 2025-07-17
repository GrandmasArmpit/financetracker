# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import datetime
import os
import json # Import json module for serializing/deserializing data

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- Configuration ---
# Database configuration from your docker-compose.yml
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admindb:Maggie13!@localhost:5432/financedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for JWT. IMPORTANT: Change this to a strong, random string in production!
# For development, you can set it directly or use an environment variable.
# Example: export SECRET_KEY='your_super_secret_key_here'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_you_should_change')
app.config['JWT_EXPIRATION_DAYS'] = 7 # JWT token valid for 7 days

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Models ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # One-to-one relationship with FinancialData
    financial_data = db.relationship('FinancialData', backref='user', uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'

class FinancialData(db.Model):
    __tablename__ = 'financial_data'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    cash = db.Column(db.Float, default=0.0)
    transactions = db.Column(db.Text, default='[]') # Store as JSON string
    credit_cards = db.Column(db.Text, default='[]') # Store as JSON string

    def __repr__(self):
        return f'<FinancialData for User {self.user_id}>'

# --- JWT Authentication Decorator ---
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        # Check for 'x-access-token' in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # Also check for 'Authorization' header with 'Bearer ' prefix
        elif 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'Token is invalid or user not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    decorated.__name__ = f.__name__ # Preserve original function name for Flask
    return decorated

# --- Routes ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists!'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Create initial financial data for the new user
    initial_financial_data = FinancialData(user=new_user, cash=0.0, transactions='[]', credit_cards='[]')
    db.session.add(initial_financial_data)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials!'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=app.config['JWT_EXPIRATION_DAYS'])
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'message': 'Login successful!', 'token': token}), 200

@app.route('/save_data', methods=['POST'])
@token_required
def save_data(current_user):
    data = request.get_json()
    cash = data.get('cash')
    transactions = data.get('transactions')
    credit_cards = data.get('creditCards')

    if cash is None or transactions is None or credit_cards is None:
        return jsonify({'message': 'Missing data fields!'}), 400

    financial_data = FinancialData.query.filter_by(user_id=current_user.id).first()
    if not financial_data:
        # This should ideally not happen if data is created on registration, but as a fallback
        financial_data = FinancialData(user_id=current_user.id)
        db.session.add(financial_data)

    financial_data.cash = cash
    financial_data.transactions = json.dumps(transactions) # Store list as JSON string
    financial_data.credit_cards = json.dumps(credit_cards) # Store list as JSON string
    db.session.commit()

    return jsonify({'message': 'Data saved successfully!'}), 200

@app.route('/load_data', methods=['GET'])
@token_required
def load_data(current_user):
    financial_data = FinancialData.query.filter_by(user_id=current_user.id).first()
    if not financial_data:
        # Return default empty data if no financial data exists for the user
        return jsonify({
            'cash': 0.0,
            'transactions': [],
            'creditCards': []
        }), 200

    return jsonify({
        'cash': financial_data.cash,
        'transactions': json.loads(financial_data.transactions), # Load JSON string back to list
        'creditCards': json.loads(financial_data.credit_cards) # Load JSON string back to list
    }), 200

# --- Database Initialization ---
# This part will create tables if they don't exist.
# It's good for development, but for production, you might use Flask-Migrate.
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
