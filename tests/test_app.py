import unittest
import json
from io import BytesIO
from src.app import app
from flask import session

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'testsecret'
        self.client = app.test_client()

    def get_csrf_token(self):
        """Helper function to fetch a valid CSRF token from the app."""
        response = self.client.get('/')
        csrf_token = response.data.decode().split('name="csrf_token" value="')[1].split('"')[0]
        return csrf_token

    def test_index_get(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Upload your JSON configuration file', response.data)

    def test_upload_post_no_file(self):
        csrf_token = self.get_csrf_token()
        response = self.client.post('/upload', data={'csrf_token': csrf_token}, follow_redirects=True)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {"error": "No file part"}) 

    def test_upload_post_empty_file(self):
        csrf_token = self.get_csrf_token()
        data = {
            'csrf_token': csrf_token,
            'config_file': (BytesIO(b''), '')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {"error": "No selected file"})  

    def test_upload_post_invalid_json(self):
        csrf_token = self.get_csrf_token()
        data = {
            'csrf_token': csrf_token,
            'config_file': (BytesIO(b'Not valid JSON!'), 'config.json')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {"error": "Invalid JSON format."}) 

    def test_upload_post_valid_json_no_vulns(self):
        csrf_token = self.get_csrf_token()
        good_json = json.dumps({
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm-secure",
                    "open_ports": [],
                    "password": "ENC(verysecureencryptedvalue)",
                    "encryption": True,
                    "mfa_enabled": True
                }
            ]
        })
        data = {
            'csrf_token': csrf_token,
            'config_file': (BytesIO(good_json.encode('utf-8')), 'config.json')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No vulnerabilities found.", response.data)

    def test_download_csv_no_vulns(self):
        with self.client as c:
            response = c.get('/download_csv', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"No vulnerabilities to export.", response.data)

if __name__ == '__main__':
    unittest.main()
