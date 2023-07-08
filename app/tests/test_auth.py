

import unittest
from unittest.mock import patch
from dotenv import dotenv_values
from sys import path as spath
import logging
from app import create_app
from app import auth
from app.models.user import User

logging.basicConfig(level=logging.DEBUG)

class AuthTestCase(unittest.TestCase):

    def setUp(self):
        logging.warning(f"setup")
        # Set up the testing environment
        self.app, self.db = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Create all database tables
        self.db.create_all()

        # Create an instance of the Auth class
        self.auth = auth

    def tearDown(self):
        logging.warning(f"teardown")
        self.db.drop_all()
        self.app_context.pop()
        

    def test_register_user(self):
        logging.warning(f"runnign test reg user")
        username = 'test_user'
        password = 'test_password'
        registration_data = {'username': username, 'password': password}

        response = self.app.test_client().post('/auth/register', json=registration_data)

        # Assert that the response status code is 200 (success)
        self.assertEqual(response.status_code, 200)

        # Assert that the response message indicates successful registration
        expected_message = {'message': 'Registration successful'}
        self.assertEqual(response.json, expected_message)

        # Assert that the new user is added to the database
        new_user = User.query.filter_by(username=username).first()
        self.assertIsNotNone(new_user)
        self.assertEqual(new_user.username, username)
        # ... add more assertions to check other user attributes if necessary

        # Clean up by deleting the new user from the database
        # self.db.session.delete(new_user)
        # self.db.session.commit()

    #def test_login_user(self):
        # Test the login functionality
        pass

    #def test_logout_user(self):
        # Test the logout functionality
        pass

    #def test_access_protected_route(self):
        # Test accessing a protected route with valid credentials
        pass

    #def test_access_protected_route_unauthenticated(self):
        # Test accessing a protected route without authentication
        pass

    #def test_access_protected_route_expired_token(self):
        # Test accessing a protected route with an expired token
        pass


if __name__ == '__main__':
    logging.warning(f"starting unittestmain")
    unittest.main()
