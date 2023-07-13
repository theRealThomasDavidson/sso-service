import unittest
from app import app, db
from app.models.user import User
from random import randint
from time import time, sleep
import jwt
from codecs import encode
from json import loads as jsload
import base64
import bcrypt
from hashlib import sha3_512
from datetime import datetime, timedelta


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        # Set up the Flask app for testing
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'sekrit!'
        with app.app_context():
            # Create the database tables
            db.create_all()
        self.app = app.test_client()

    def tearDown(self):
        with app.app_context():
            # Clean up the database tables
            db.session.remove()
            db.drop_all()
    
    def generate_unique_username(self, username):
        timestamp = str(int(time() * 1000))[-3:]  # Append a timestamp
        random_suffix = str(randint(1, 999))  # Append a random suffix
        return f"{username}{timestamp}{random_suffix}"
    
    def register_user(self, username, password):
        register_data = {'username': username, 'password': password, "email": "beej@hoax.json"}
        return self.app.post('auth/register', json=register_data)
    
    def set_pass(self, password, salt, nonce):
        b_hashed_password = bcrypt.hashpw(password.encode(), salt.encode())
        sn_hashed_password = sha3_512((b_hashed_password.decode()+nonce).encode())
        return base64.urlsafe_b64encode(sn_hashed_password.digest()).decode()

    def login_user(self, username, password):
        while True:
            self.register_user(username, password)
            login_data_1 = {'username': username}
            response = self.app.post("auth/login/challenge", json=login_data_1)
            salt = response.get_json()["salt"]
            nonce = response.get_json()["nonce"]
            login_data_2 = {'password': self.set_pass(password, salt, nonce)}
            response = self.app.post("auth/login/answer", json=login_data_2)
            if response.status_code != 200:
                username = self.generate_unique_username(username)
            return response.get_json()['jwt']
    
    def logout_user(self, jwt): 
        endpoint = 'auth/logout'
        headers = {'Authorization': f'Bearer {jwt}'}
        return self.app.post(endpoint, headers=headers)
    def verify_jwt(self, jwt):
        """
        Verify the given JWT by accessing the verify endpoint. 

        Args:
            jwt (str): The JWT token to verify.

        Returns:
            Flask response: The response object from accessing the verify endpoint.

        """
        verify_endpoint = 'auth/verify'
        headers = {'Authorization': f'Bearer {jwt}'}
        response = self.app.get(verify_endpoint, headers=headers)
        return response

    def test_dummy(self):
        # Dummy test method
        self.assertTrue(True)

    def test_hello_endpoint(self):
        response = self.app.get('/jwtfree')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), 'Hello! This is a non-JWT required endpoint.')
    
    
    def test_register_endpoint(self):
        """
        Test the registration endpoint.
        ... (existing code) ...

        Assertions:
        - Verify the response status code and message for each test case.
        - Check if the user is created in the database for a successful registration.
        - Ensure the duplicate username registration returns the appropriate status code.
        """

        endpoint = 'auth/register'
        http_method = self.app.post

        # Prepare test data
        username = 'test_user'
        password = 'test_password'

        # Successful registration with a unique username, password, and properly formatted email
        data = {'username': username, 'password': password, 'email': 'beej@hoax.json'}
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 201)

        # Malformed request with an empty username
        data = {'password': password, 'email': 'beej@hoax.json'}
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 400)

        # Malformed request with an empty password
        username2 = 'test_user2'
        data = {'username': username2, 'email': 'beej@hoax.json'}
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 400)

        # Malformed request with an improperly formatted email
        username3 = 'test_user3'
        data = {'username': username3, 'password': password, 'email': 'invalid_email'}
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 400)
        # Malformed request with no email
        username3 = 'test_user3'
        data = {'username': username3, 'password': password, }
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 400)

        # Registration attempt with a duplicate username
        data = {'username': username, 'password': password, 'email': 'beej@hoax.json'}
        response = http_method(endpoint, json=data)
        self.assertEqual(response.status_code, 409)

        # Verify that the duplicate username was not created in the database
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            self.assertIsNotNone(user)
            self.assertEqual(user.username, username)


    def test_login_endpoint(self):
        """
        Test the login endpoint.

        This method tests the login functionality of the `/auth/login` endpoint.
        It verifies that a user can successfully log in with a valid username and password.
        The presence of an authentication JWT is not considered in this test since it
        doesn't impact the logic or behavior of the login process. The assumption is
        that the login process should only check the validity of the username and password.

        Note: Once a frontend is implemented, the frontend will take care of hashing the
        salt and nonce on the client-side to prevent exposing them to logs or potential
        man-in-the-middle attacks. This test assumes the current behavior of hashing on
        the server-side.

        Test Cases:
        - Successful login with a valid username and password.
        - Invalid login attempt with an incorrect username.
        - Invalid login attempt with an incorrect password.

        Assertions:
        - Verify the response status code and message for each test case.
        - Check if a JWT is returned for a successful login.
        - Ensure an appropriate error message is returned for invalid login attempts.
        - Verify that a user's JWT is unregistered upon subsequent logins.

        """
        endpoint = 'auth/login'
        http_method = self.app.post

        # Register a user
        username = self.generate_unique_username('test_user_login_')
        password = 'test_password'
        self.register_user(username, password)
        # Test successful login
        login_data = {'username': username, 'password': password}
        response = http_method(endpoint, json=login_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('jwt', response.get_json())

        jwt_token = response.get_json()['jwt']
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            expected_user_id = user.id
        try:
            decoded_token = jwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
            self.assertEqual(decoded_token['sub'], expected_user_id) 
        except jwt.ExpiredSignatureError:
            self.fail("JWT has expired")
        except jwt.InvalidTokenError:
            self.fail("Invalid JWT")


        # Test invalid username
        invalid_username_data = {'username': 'invalid_username', 'password': password}
        response = http_method(endpoint, json=invalid_username_data)
        self.assertEqual(response.status_code, 401)
        # Test invalid password
        invalid_password_data = {'username': username, 'password': 'invalid_password'}
        response = http_method(endpoint, json=invalid_password_data)
        self.assertEqual(response.status_code, 401)


    def test_verify_endpoint(self):
        """
        Test the verify endpoint.

        This method tests the functionality of the `/auth/verify` endpoint.
        It verifies that the endpoint requires a valid JWT for access.

        Test Case:
        - Access the endpoint without a valid JWT.

        Assertion:
        - Verify the response status code for the test case.

        """
        endpoint = 'auth/verify'
        http_method = self.app.get

        # Access the endpoint without a valid JWT
        response = http_method(endpoint)
        self.assertEqual(response.status_code, 401)
        user = "user_to_verify"
        password = "pass"
        jwt = self.login_user(user, password)
        headers = {'Authorization': f'Bearer {jwt}'}
        response = self.app.get(endpoint, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(user, jsload(response.get_data()).get("username"))
        #JUNK JWT SIGNATURE
        jwt2 =  jwt[:-20] + encode(jwt[-20:], "rot_13")
        headers = {'Authorization': f'Bearer {jwt2}'}
        response = self.app.get(endpoint, headers=headers)
        self.assertEqual(response.status_code, 422)
        #JUNK payload
        payload = jwt.split('.')[1]  # Extract the payload part of the JWT
        decoded_payload = base64.urlsafe_b64decode(payload + '===').decode()  # Decode the Base64 payload
        junk_payload = decoded_payload[:-1] + '}'  # Modify the payload by adding an invalid character
        junk_jwt = '.'.join([jwt.split('.')[0], base64.urlsafe_b64encode(junk_payload.encode()).decode(), jwt.split('.')[2]])
        headers = {'Authorization': f'Bearer {junk_jwt}'}
        response = self.app.get(endpoint, headers=headers)
        self.assertEqual(response.status_code, 422)
        #expired jwt
        register_data = {'username': user, 'password': password, "token_duration_seconds": 1}
        response = self.app.post('auth/login', json=register_data)
        if response.status_code != 200:
            username = self.generate_unique_username(username)
        expired_jwt = response.get_json()['jwt']
        sleep(2)
        headers = {'Authorization': f'Bearer {expired_jwt}'}
        response = self.app.get(endpoint, headers=headers)
        self.assertEqual(response.status_code, 401)


    def test_logout_endpoint(self):
        """
        Test the logout endpoint.

        This method tests the functionality of the `/auth/logout` endpoint.
        It verifies that a logged-in user can successfully revoke their JWT token.

        Test Case:
        - Login with valid credentials and obtain a JWT.
        - Access the verify endpoint with the JWT and verify its validity.
        - Logout by revoking the JWT.
        - Attempt to access the verify endpoint again with the revoked JWT.

        Assertions:
        - Verify the response status codes and messages for each test case.
        - Ensure the JWT is successfully revoked.
        - Verify that the revoked JWT is no longer valid.

        """
        logout_endpoint = 'auth/logout'
        http_method = self.app.post

        # Register a user and obtain a valid JWT
        username = self.generate_unique_username('test_user')
        password = 'test_password'
        jwt = self.login_user(username, password)
        # Verify the JWT by accessing the verify endpoint
        verify_response = self.verify_jwt(jwt)
        self.assertEqual(verify_response.status_code, 200)
        # Logout by revoking the JWT
        logout_headers = {'Authorization': f'Bearer {jwt}'}
        logout_response = http_method(logout_endpoint, headers=logout_headers)
        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(logout_response.get_json()['message'], 'JWT revoked successfully')

        # Attempt to access the verify endpoint again with the revoked JWT
        verify_response = self.verify_jwt(jwt)
        self.assertEqual(verify_response.status_code, 401)
         
    def test_delete_user_endpoint(self):  
        """
        Test the delete_user endpoint.

        This method tests the functionality of the `/auth/delete_user` endpoint.
        It verifies that a logged-in user can successfully delete their account and
        that the account is properly revoked.

        Test Steps:
        1. Create a new user and log in.
        2. Verify that the user can access the verify endpoint.
        3. Delete the user account.
        4. Verify that the user cannot access the verify endpoint.
        5. Verify that the user cannot log in.
        6. Verify that attempting to delete the user again returns a 404 status.

        Assertions:
        - Verify the response status code and message for each test step.
        - Check if the user account is deleted from the database.
        - Ensure that subsequent attempts to access protected endpoints fail.

        """
        endpoint_login = 'auth/login'
        endpoint_delete = 'auth/delete_user'
        http_method = self.app.delete

        # Step 1: Create a new user and log in
        username = 'user_delete_'
        password = 'test_password'
        jwt_token = self.login_user(username, password)

        # Step 2: Verify that the user can access the verify endpoint
        response = self.verify_jwt(jwt_token)
        self.assertEqual(response.status_code, 200)

        # Step 3: Delete the user account
        headers = {'Authorization': f'Bearer {jwt_token}'}
        response = http_method(endpoint_delete, headers=headers)
        self.assertEqual(response.status_code, 204)

        # Step 4: Verify that the user cannot access the verify endpoint
        response = self.verify_jwt(jwt_token)
        self.assertEqual(response.status_code, 401)

        # Step 5: Verify that the user cannot log in
        response = self.app.post(endpoint_login, json={'username': username, 'password': password})
        self.assertEqual(response.status_code, 401)

        # Step 6: Verify that attempting to delete the user again returns a 401 status
        response = http_method(endpoint_delete, headers=headers)
        self.assertEqual(response.status_code, 401)

    
    def test_update_password(self):
        # Step 1: Create a new user
        username = 'user_update_'
        initial_password = 'initial_pass'
        self.register_user(username, initial_password)

        # Define the HTTP method
        http_method = self.app.post
        endpoint_update_password = 'auth/update_password'

        # Step 2: Verify JWT
        jwt_token = self.login_user(username, initial_password)
        verify_response = self.verify_jwt(jwt_token)
        self.assertEqual(verify_response.status_code, 200)

        # Step 3: Logout
        self.logout_user(jwt_token)

        # Step 4: Test update password with missing initial password
        new_password = 'new_pass'
        response = http_method(
            endpoint_update_password,
            json={'username': username, 'new_password': new_password}
        )
        self.assertEqual(response.status_code, 400)
        response = self.app.post("auth/login", json={'username': username, 'password': new_password} )
        self.assertNotIn('jwt', response.get_json())

        # Step 5: Test update password with incorrect initial password
        response = http_method(
            endpoint_update_password,
            json={
                'username': username,
                'old_password': 'wrong_password',
                'new_password': new_password
            }
        )
        self.assertEqual(response.status_code, 401)
        response = self.app.post("auth/login", json={'username': username, 'password': new_password} )
        self.assertNotIn('jwt', response.get_json())

        # Step 6: Update password
        response = http_method(
            endpoint_update_password,
            json={
                'username': username,
                'old_password': initial_password,
                'new_password': new_password
            }
        )
        self.assertEqual(response.status_code, 201)

        # Step 7: Verify old password is no longer valid
        response = self.app.post("auth/login", json={'username': username, 'password': initial_password} )
        self.assertNotIn('jwt', response.get_json())

        # Step 8: Verify new password is valid
        jwt_token = self.login_user(username, new_password)
        verify_response = self.verify_jwt(jwt_token)
        self.assertEqual(verify_response.status_code, 200)


    def test_login_challenge_endpoint(self):
        
        endpoint_1 = 'auth/login/challenge'
        http_method_1 = self.app.post
        endpoint_2 = 'auth/login/answer'
        http_method_2 = self.app.post
        username = self.generate_unique_username('test_user_login_challenge_')
        password = 'test_password'
        self.register_user(username, password)
        # Test successful login
        login_data_1 = {'username': username}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertEqual(response.status_code, 200)
        self.assertIn('salt', response.get_json())
        self.assertIn('nonce', response.get_json())
        salt = response.get_json()["salt"]
        nonce = response.get_json()["nonce"]
        login_data_2 = {'password': self.set_pass(password, salt, nonce)}
        response = http_method_2(endpoint_2, json=login_data_2)
        self.assertEqual(response.status_code, 200)
        self.assertIn('jwt', response.get_json())
        #verify successful login with jwt
        jwt = response.get_json()['jwt']
        verify_resp = self.verify_jwt(jwt)
        self.assertEqual(verify_resp.status_code, 200)
        self.assertEqual(username, jsload(verify_resp.get_data()).get("username"))
        # test no username
        login_data_1 = {}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertEqual(response.status_code, 400)
        # test incorrect username
        bad_username = self.generate_unique_username('bad_username_')
        login_data_1 = {'username': bad_username}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertEqual(response.status_code, 200)
        self.assertIn('salt', response.get_json())
        self.assertIn('nonce', response.get_json())
        salt = response.get_json()["salt"]
        nonce = response.get_json()["nonce"]
        login_data_2 = {'password': self.set_pass(password, salt, nonce)}
        response = http_method_2(endpoint_2, json=login_data_2)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('jwt', response.get_json())
        #test incorrect username receives the same salt
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(salt, response.get_json()["salt"])
        # Test timeout scenario
        login_data_1 = {'username': username}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertIn('salt', response.get_json())
        self.assertIn('nonce', response.get_json())
        salt = response.get_json()["salt"]
        nonce = response.get_json()["nonce"]
        sleep(11)  # Sleep for 11 seconds to simulate timeout
        login_data_2 = {'password': self.set_pass(password, salt, nonce)}
        response = http_method_2(endpoint_2, json=login_data_2)
        self.assertEqual(response.status_code, 410)
        self.assertNotIn('jwt', response.get_json())

        # Test incorrect password (plaintext)
        login_data_1 = {'username': username}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertIn('salt', response.get_json())
        self.assertIn('nonce', response.get_json())
        salt = response.get_json()["salt"]
        nonce = response.get_json()["nonce"]
        login_data_2 = {'password': password}
        response = http_method_2(endpoint_2, json=login_data_2)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('jwt', response.get_json())

        # Test incorrect password (hashed)
        login_data_1 = {'username': username}
        response = http_method_1(endpoint_1, json=login_data_1)
        self.assertIn('salt', response.get_json())
        self.assertIn('nonce', response.get_json())
        salt = response.get_json()["salt"]
        nonce = response.get_json()["nonce"]
        incorrect_hashed_password = self.set_pass('incorrect_password', salt, nonce)
        login_data_2 = {'password': incorrect_hashed_password}
        response = http_method_2(endpoint_2, json=login_data_2)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('jwt', response.get_json())


if __name__ == '__main__':
    unittest.main()