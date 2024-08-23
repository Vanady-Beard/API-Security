from flask import Blueprint, request, jsonify
from .models import User
from . import db
from .utils.util import encode_token, decode_token
from functools import wraps

main = Blueprint('main', __name__)

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    print(f"Login attempt for username: {username}")  # Debugging information

    user = User.query.filter_by(username=username).first()
    if user:
        print(f"User found: {user.username}")  # Debugging information
        if user.check_password(password):
            print("Password is correct")  # Debugging information
            token = encode_token(user.id)
            return jsonify({'token': token}), 200
        else:
            print("Password is incorrect")  # Debugging information
    else:
        print("User not found")  # Debugging information

    return jsonify({'message': 'Invalid credentials'}), 401

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization').split()[1]
            user_id = decode_token(token)
            user = User.query.get(user_id)
            if user.role != role:
                return jsonify({'message': 'Access forbidden: insufficient rights'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@main.route('/admin-only', methods=['POST'])
@role_required('admin')
def admin_only():
    return jsonify({'message': 'Welcome, admin!'})

@main.before_app_request
def create_default_admin():
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin')
        admin_user.set_password('password')
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")  # Debugging information
    else:
        print("Admin user already exists")  # Debugging information

