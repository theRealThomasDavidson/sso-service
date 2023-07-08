from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from os import environ
from urllib.parse import quote
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
import logging
from dotenv import dotenv_values

dotenv_name = {"development": '.env', "testing": '.env.testing'}
app = None
db = SQLAlchemy()  # Create an instance of SQLAlchemy
migrate = Migrate()
SWAGGER_URL = '/api/docs'  # URL for exposing Swagger UI (without trailing '/')
# Our API url (can of course be a local resource)
API_URL = '../swag.json'
logging.basicConfig(level=logging.DEBUG)

def create_app(config="development"):
    app = Flask(__name__)

    # Configuration and other app setup
    if config in dotenv_name:
        app.config['SQLALCHEMY_DATABASE_URI'] = generate_database_uri(dotenv_name[config])
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = generate_database_uri(dotenv_name["development"])
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET_KEY')

    # Initialize the db object with your Flask application
    db.init_app(app)
    migrate.init_app(app, db)

    jwt = JWTManager(app)
    from app.models.revoked_tokens import RevokedToken

    @jwt.token_in_blocklist_loader
    def check_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        # Check if the token jti is in the blacklist
        is_revoked = RevokedToken.is_jti_blacklisted(jti)
        return is_revoked

    @jwt.revoked_token_loader
    def handle_revoked_token(jwt_header, jwt_payload):
        return jsonify({"message": "Token has been revoked"}), 401

    from app.controller import app_bp
    from app.auth.auth import auth_bp
    from flask_swagger_ui import get_swaggerui_blueprint

    swaggerui_blueprint = get_swaggerui_blueprint(
        # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
        SWAGGER_URL,
        API_URL,
        config={  # Swagger UI config overrides
            'app_name': "Test application"
        },
    )

    app.register_blueprint(app_bp, url_prefix='/app')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(swaggerui_blueprint)

    return app


def generate_database_uri(dotenv_path=".env"):
    env_vars = dotenv_values(dotenv_path)
    db_username = env_vars.get('DB_USERNAME')
    db_password = env_vars.get('DB_PASSWORD')
    db_host = env_vars.get('DB_HOST')
    db_name = env_vars.get('DB_NAME')

    # Encode the username and password as bytes
    encoded_username = quote(db_username.encode('utf-8'), safe='')
    encoded_password = quote(db_password.encode('utf-8'), safe='')

    # Construct the database URI with encoded username and password
    return f'mysql+pymysql://{encoded_username}:{encoded_password}@{db_host}/{db_name}'

app = create_app()


@app.route('/', methods=['GET'])
def hello():
    return 'Hello! This is a non-JWT required endpoint.'