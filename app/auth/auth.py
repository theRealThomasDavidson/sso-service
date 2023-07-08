from flask import jsonify, request, Blueprint
from app.models.user import User
from app import db
import bcrypt
import secrets
import jwt
from os import environ
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models.revoked_tokens import RevokedToken
from uuid import uuid4

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    # Get the registration data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Malformed request'}), 400

    # Check if the username already exists in the database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists. Please choose a different username.'}), 409

    try:
        # Generate a random nonce
        nonce = secrets.token_hex(16)

        # Generate salt for the user
        salt = bcrypt.gensalt().decode()

        # Hash the password with the user's salt and the nonce
        hashed_password = bcrypt.hashpw(
            (password + nonce).encode(), salt.encode())

        # Create a new user with the hashed password and salt
        user = User(username=username, password=hashed_password, salt=salt)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'Registration successful'})
    except Exception as e:
        # Handle any other exceptions that may occur during user creation
        return jsonify({'message': 'An error occurred during user registration.'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    # Get the login data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Malformed request'}), 400

    user = User.query.filter_by(username=username).first()

    if user:
        # Generate a random nonce
        nonce = secrets.token_hex(16)

        # Hash the password with the user's salt and the nonce
        hashed_password = bcrypt.hashpw(
            (password + nonce).encode(), user.salt.encode())

        if bcrypt.checkpw((password + nonce).encode(), hashed_password):
            # Authentication successful, generate JWT
            payload = {
                # Subject claim (can be user ID or any identifier)
                'sub': user.id,
                'nonce': nonce,  # Include nonce in the JWT payload
                'jti': str(uuid4()),
            }
            jwt_token = jwt.encode(
                payload, environ.get('JWT_SECRET_KEY'), algorithm='HS256')

            return jsonify({'message': 'Login successful', 'jwt': jwt_token})

    return jsonify({'message': 'Invalid username or password'})


@auth_bp.route('/delete_user', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()

    try:
        # Delete the user
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'message': 'User not found.'}), 404

        db.session.delete(user)

        revoked_token = RevokedToken(jti=get_jwt()['jti'])
        db.session.add(revoked_token)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'})
    except Exception as e:
        # Handle any other exceptions that may occur during deletion
        return jsonify({'message': 'An error occurred during user deletion.'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    if not get_jwt():
        return jsonify({'message': 'Not logged in'}), 401

    jti = get_jwt()['jti']  # Get the JTI (JWT ID) from the current JWT
    try:
        # Create a new RevokedToken instance with the JTI
        revoked_token = RevokedToken(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()

        return jsonify({'message': 'JWT revoked successfully'})
    except Exception as e:
        # Handle any exceptions that may occur during revocation
        return jsonify({'message': 'An error occurred during JWT revocation.'}), 500
