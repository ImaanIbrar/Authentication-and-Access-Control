import socket
import unittest
from datetime import datetime
from unittest.mock import patch
import hashlib

from flask import Flask

from app import (LOGIN_ATTEMPTS, app, authenticate_user, check_location_access,
                 check_working_hours, generate_otp, get_attributes_dict,
                 get_stored_otp, grant_access, increment_failed_login_attempts,
                 send_otp_email, set_stored_otp)


class FlaskAppTests(unittest.TestCase):
    
    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()

    def test_main_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_invalid_authentication(self):
        response = self.app.post('/', data=dict(Email='invalid@example.com', Password='wrongpassword'))
        self.assertIn(b'Authentication failed', response.data)

    def test_valid_authentication(self):
        response = self.app.post('/', data=dict(Email='lpddqleudu86@jpdlo.frp', Password='sdvvzrug'))
    
    
        self.assertEqual(response.status_code, 200)
        
        self.assertIn(b'<button type="submit">Verify OTP and Grant Access</button>', response.data)
        

    def test_otp_verification(self):
        # Assuming a valid OTP is generated
        valid_otp = generate_otp()

        # Set the stored OTP for verification
        set_stored_otp(valid_otp)

        # Verify OTP endpoint
        response = self.app.post('/verify_otp_and_grant_access', data=dict(otp=valid_otp, resource='Project'))
        self.assertIn(b'Access denied', response.data)

    def test_access_denied(self):
        # Assuming a valid OTP is generated
        valid_otp = generate_otp()

        # Set the stored OTP for verification
        set_stored_otp(valid_otp)

        # Verify OTP endpoint with incorrect resource
        response = self.app.post('/verify_otp_and_grant_access', data=dict(otp=valid_otp, resource='InvalidResource'))
        self.assertIn(b'Access denied', response.data)


    def test_check_location_access(self):
        # Assuming the host IP is the required IP
        with self.subTest(msg="Valid IP Address"):
            self.assertTrue(check_location_access())

        # Assuming the host IP is not the required IP
        with self.subTest(msg="Invalid IP Address"):
            socket.gethostbyname = lambda x: '192.178.1.1'  # an invalid IP
            self.assertFalse(check_location_access())

    
    @patch('app.datetime', autospec=True)
    def test_check_working_hours(self,mocked_datetime):
        # Assuming the current time is within working hours
            mocked_datetime.now.return_value = datetime(2024, 1, 1, 9, 0, 0)  
            print(check_working_hours())
            self.assertTrue(check_working_hours())

        # Assuming the current time is outside working hours
        
            mocked_datetime.now.return_value = datetime(2024, 1, 1, 23, 0, 0)  
            print(check_working_hours())
            self.assertFalse(check_working_hours())



#-------------------------------------------------------------
    def test_successful_login_and_otp_verification(self):
            with patch('app.authenticate_user', return_value=True), \
                patch('app.generate_otp', return_value='123'), \
                patch('app.send_otp_email'), \
                patch('app.get_stored_otp', return_value={'otp': '123', 'timestamp': datetime.now()}), \
                patch('app.grant_access', return_value=True):

                # Simulate successful login
                response_login = self.app.post('/', data=dict(Email='mnaeem.bese21seecs@seecs.edu.pk', Password='password'))
                self.assertEqual(response_login.status_code, 200)
                self.assertIn(b'OTP Verification', response_login.data)

                # Simulate OTP verification and access granting
                response_verify_otp = self.app.post('/verify_otp_and_grant_access',
                                                    data=dict(otp='123', resource='Project'))
                self.assertEqual(response_verify_otp.status_code, 200)
                self.assertIn(b'Access granted', response_verify_otp.data)

    def test_unsuccessful_login_incorrect_credentials(self):
        with patch('app.authenticate_user', return_value=False):
            response = self.app.post('/', data=dict(Email='mnaeem.bese21seecs@seecs.edu.pk', Password='wrong_password'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Authentication failed. Please check your credentials.', response.data)

    def test_unsuccessful_login_account_locked(self):
        # Set the number of login attempts to reach the lockout threshold
        LOGIN_ATTEMPTS['mnaeem.bese20seecs@seecs.edu.pk'] = {'attempts': 7, 'timestamp': '2023-01-01 00:00:00.000'}

        with patch('app.is_user_locked_out', return_value=True):
            response = self.app.post('/', data=dict(Email='mnaeem.bese21seecs@seecs.edu.pk', Password='wrong_password'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Account locked due to multiple unsuccessful login attempts. Please contact System Adminstartor to access your account.', response.data)

    def test_unsuccessful_otp_verification(self):
        with patch('app.get_stored_otp', return_value={'otp': '654', 'timestamp': None}), \
             patch('app.grant_access', return_value=False):

            response = self.app.post('/verify_otp_and_grant_access', data=dict(otp='123', resource='Project'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Authentication failed due to Incorrect OTP', response.data)


    def test_get_attributes_dict(self):
            # Arrange
            expected_users_info = [
            {
                'email': 'mnaeem.bese21seecs@seecs.edu.pk',
                'password': hashlib.sha3_256('password'.encode()).hexdigest(),
                'Role': 'Project_Manager',
                'status': 'Locked'
            },
            {
                'email': 'imaanibrar86@gmail.com',
                'password': hashlib.sha3_256('password'.encode()).hexdigest(),
                'Role': 'Developer',
                'status': 'Locked'
            },
            {
                'email': 'skdjskanwaar.bese21seecs@seecs.edu.pk',
                'password': hashlib.sha3_256('password'.encode()).hexdigest(),
                'Role': 'Project_Manager',
                'status': 'Locked'
            },
            {
                'email': 'mnaeem.bese21seecs@seecs.edu.pk',
                'password': hashlib.sha3_256('password'.encode()).hexdigest(),
                'Role': 'SQA_Engineer',
                'status': 'Unlocked'
            },
            {
                'email': 'sanwaar.bese21seecs@seecs.edu.pk',
                'password': hashlib.sha3_256('password'.encode()).hexdigest(),
                'Role': 'Developer',
                'status': 'Unlocked'
            }
        ]

            # Act
            result = get_attributes_dict()

            # Assert
            self.assertEqual(result, expected_users_info)
if __name__ == '__main__':
    unittest.main()
