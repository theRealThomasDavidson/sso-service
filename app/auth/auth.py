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
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

def create_response(status_code, message="", data=None):
    response = {
        'status': status_code,
    }
    if message:
        response["message"] = message
    if data is not None:
        response.update(data)
    return jsonify(response), status_code

#CREATE
@auth_bp.route('/register', methods=['POST'])
def register():
    # Get the registration data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return create_response(400, 'Malformed request')

    # Check if the username already exists in the database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return create_response(409, 'Username already exists. Please choose a different username.')

    try:
        # Generate salt for the user
        salt = bcrypt.gensalt().decode()

        # Hash the password with the user's salt and the nonce
        hashed_password = bcrypt.hashpw(
            password.encode(), salt.encode())

        # Create a new user with the hashed password and salt
        user = User(username=username, password=hashed_password, salt=salt)
        db.session.add(user)
        db.session.commit()

        return create_response(201, 'Registration successful')
    except Exception as e:
        # Handle any other exceptions that may occur during user creation
        return create_response(500, 'An error occurred during user registration.')


#UPDATE
@auth_bp.route('/update_password', methods=['POST'])
def update_password():
    # Check if the request contains the required JSON fields
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not username or not old_password or not new_password:
        return create_response(400, 'Malformed request')

    # Check if the provided credentials are valid
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(old_password.encode(), user.password.encode()):
        return create_response(401, 'Invalid username or password')

    try:
        # Generate a new salt and hash the new password
        new_salt = bcrypt.gensalt().decode()
        new_hashed_password = bcrypt.hashpw(new_password.encode(), new_salt.encode())

        # Update the user's password and salt in the database
        user.password = new_hashed_password
        user.salt = new_salt
        db.session.commit()

        return create_response(201, 'Password updated')
    except Exception as e:
        return create_response(500, 'An error occurred during password update.')
#DELETE
@auth_bp.route('/delete_user', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()

    try:
        # Delete the user
        user = db.session.get(User, current_user_id)
        if not user:
            return create_response(404, 'User not found.')

        db.session.delete(user)

        revoked_token = RevokedToken(jti=get_jwt()['jti'])
        db.session.add(revoked_token)
        db.session.commit()

        return create_response(204, 'User deleted successfully')
    except Exception as e:
        # Handle any other exceptions that may occur during deletion
        return create_response(500, 'An error occurred during user deletion.')



#authentication
@auth_bp.route('/login', methods=['POST'])
def login():
    # Get the login data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    exp = data.get('token_duration_seconds')
    if not exp:
        td_exp = timedelta(minutes=75)
    else:
        td_exp = timedelta(seconds=min(75 * 60,exp ))
    if not username or not password:
        return create_response(400, 'Malformed request')

    user = User.query.filter_by(username=username).first()

    if user:

        # Hash the password with the user's salt and the nonce
        hashed_password = bcrypt.hashpw(
            (password).encode(), user.salt.encode())

        if (user.password.encode() == hashed_password):
            # Authentication successful, generate JWT
            payload = {
                # Subject claim (can be user ID or any identifier)
                'sub': user.id,
                'jti': str(uuid4()),
                'exp': datetime.utcnow() + td_exp
            }
            jwt_token = jwt.encode(
                payload, environ.get('JWT_SECRET_KEY'), algorithm='HS256')

            return create_response(200, 'Login successful', {'jwt': jwt_token})

    return create_response(401, 'Invalid username or password')


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    if not get_jwt():
        return create_response(401, 'Not logged in')

    jti = get_jwt()['jti']  # Get the JTI (JWT ID) from the current JWT
    try:
        # Create a new RevokedToken instance with the JTI
        revoked_token = RevokedToken(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()

        return create_response(200, 'JWT revoked successfully')
    except Exception as e:
        # Handle any exceptions that may occur during revocation
        return create_response(500, 'An error occurred during JWT revocation.')

#authorization
@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def confirm():
    # Get the user ID from the JWT payload
    user_id = get_jwt_identity()

    # Fetch the user from the database based on the user ID
    user = db.session.query(User).get(user_id)

    # Return the username and user ID as JSON response
    return create_response(200, data={'username': user.username, 'user_id': user.id})