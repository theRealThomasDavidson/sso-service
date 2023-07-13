from flask import jsonify, request, Blueprint, session
from app.models.user import User
from app import db
import bcrypt
import jwt
from os import environ
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models.revoked_tokens import RevokedToken
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from hashlib import sha3_512, sha256, md5
from base64 import b64encode, b64decode, urlsafe_b64encode
from logging import warning
from flask_cors import cross_origin

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

def generate_bad_salt(username):
    mess = username.encode()  # Initial salt value is the username
    for _ in range(5):
        mess = sha256(mess + b'wrench').digest()
    salt = md5(mess).digest()[:16]
    output = bcrypt._bcrypt.encode_base64(salt)
    supposed = b"$2b$" + ("%2.2u" % 12).encode("ascii") + b"$" + output
    return supposed.decode() 

#CREATE
@auth_bp.route('/register', methods=['POST'])
def register():
    # Get the registration data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return create_response(400, 'Malformed request')

    # Check if the username already exists in the database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return create_response(409, 'Username already exists. Please choose a different username.')

    try:
        # Generate salt for the user
        salt = bcrypt.gensalt().decode()

        # Hash the password with the user's salt and the nonce
        hashed_password = bcrypt.hashpw(password.encode(), salt.encode())

        # Create a new user with the hashed password, salt, and email
        user = User(username=username, password=hashed_password, salt=salt, email=email)
        user.save()

        return create_response(201, 'Registration successful')
    except ValueError as e:
        return create_response(400, "Invalid Email")
    except Exception as e:
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

    if not user:
        return create_response(401, 'Invalid username or password')

    # Hash the password with the user's salt and the nonce
    hashed_password = bcrypt.hashpw(
        (password).encode(), user.salt.encode())

    if not (user.password.encode() == hashed_password):
        return create_response(401, 'Invalid username or password')
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



@auth_bp.route("/login/challenge", methods=["POST"])
@cross_origin(supports_credentials=True)
def login_challenge():
    TIME_OUT_SEC = 10
    data = request.get_json()
    warning(data)
    username = data.get('username')
    if not username:
        return create_response(400, data={"error": "Username is required"})
    user = User.query.filter_by(username=username).first()
    nonce = token_urlsafe()
    if not user:
        salt = generate_bad_salt(username)
    else:
        salt = user.salt
        session["username"] = user.username
        session["nonce"] = nonce
        session["timeout"] = datetime.utcnow()+timedelta(seconds=TIME_OUT_SEC)
    response_data = {
        'nonce': nonce,
        'salt': salt
    }
    return create_response(200, data=response_data)

@auth_bp.route("/login/answer", methods=["POST"])
@cross_origin(supports_credentials=True)
def login_answer():
    data = request.get_json()
    client_password = data.get('password')  # of the form sha3_512(bcrypt(password+salt), nonce)
    if not client_password:
        return create_response(400, data={"error": "please provide a password"})
    username = session.get('username')
    nonce = session.get('nonce')
    timeout = session.get("timeout")
    if not (username and nonce and timeout):
        # this comes up if a the user did not receive a challenge and therefore did not provide a correct username
        return create_response(401, data={"error": "Invalid username or password"})
    timeout = timeout.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > timeout:
        return create_response(410, {"error": "Challenge timed out."})
    data = request.get_json()
    client_password = data.get('password')  # of the form sha3_512(bcrypt(password+salt), nonce)
    exp = data.get('token_duration_seconds')
    user = User.query.filter_by(username=username).first()
    my_password = user.password
    my_password = bytes(my_password, 'utf-8')
    my_password = sha3_512((my_password.decode()+nonce).encode())
    my_password = urlsafe_b64encode(my_password.digest()).decode()
    client_password = client_password.replace(r"/", r"_").replace(r"+", r"-")
    if my_password != client_password:
        return create_response(401, data={"error": "Invalid username or password"})
    # Authentication successful, generate JWT
    if not exp:
        td_exp = timedelta(minutes=75)
    else:
        td_exp = timedelta(seconds=min(75 * 60,exp))
    payload = {
        'sub': user.id,
        'jti': str(uuid4()),
        'exp': datetime.utcnow() + td_exp
    }
    jwt_token = jwt.encode(
        payload, environ.get('JWT_SECRET_KEY'), algorithm='HS256')

    return create_response(200, 'Login successful', {'jwt': jwt_token})
    




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
    user = User.query.filter_by(id=user_id).first()

    # Return the username and user ID as JSON response
    return create_response(200, data={'username': user.username, 'user_id': user.id})