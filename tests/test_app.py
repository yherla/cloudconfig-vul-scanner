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

    def test_index_get(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Upload your JSON configuration file', response.data)

    def test_upload_post_no_file(self):
        response = self.client.post('/upload', data={}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No file part', response.data)

    def test_upload_post_empty_file(self):
        data = {
            'config_file': (BytesIO(b''), '')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No selected file', response.data)

    def test_upload_post_invalid_json(self):
        data = {
            'config_file': (BytesIO(b'Not valid JSON!'), 'config.json')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Error processing file', response.data)

    def test_upload_post_valid_json_no_vulns(self):
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
            ],
            "debug": False
        })
        data = {
            'config_file': (BytesIO(good_json.encode('utf-8')), 'config.json')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No vulnerabilities found.", response.data)

    def test_upload_post_valid_json_with_vulns(self):
        """
        Expect 4 vulnerabilities:
          1) SensitiveInformationExposure
          2) WeakPassword
          3) EncryptionDisabled
          4) OpenPortExposure
        """
        bad_json = json.dumps({
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm1",
                    "open_ports": [22],
                    "password": "weak",
                    "encryption": False,
                    "mfa_enabled": False
                }
            ]
        })
        data = {
            'config_file': (BytesIO(bad_json.encode('utf-8')), 'config.json')
        }
        response = self.client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Found 4 vulnerability(ies)", response.data)

    def test_download_csv_no_vulns(self):
        with self.client as c:
            response = c.get('/download_csv', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"No vulnerabilities to export.", response.data)

    def test_download_csv_with_vulns(self):
        with self.client as c:
            with c.session_transaction() as sess:
                sess['vulnerabilities'] = [
                    {
                        "type": "WeakPassword",
                        "key": "resources[0].password",
                        "severity": "High",
                        "message": "Example message",
                        "remediation": "Use a stronger password."
                    }
                ]
            response = c.get('/download_csv')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"WeakPassword", response.data)
            self.assertIn(b"Use a stronger password.", response.data)
            content_type = response.headers.get('Content-Type', '')
            self.assertIn("text/csv", content_type)

if __name__ == '__main__':
    unittest.main()
