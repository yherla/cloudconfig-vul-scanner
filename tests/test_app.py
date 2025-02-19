import unittest
import json
from io import BytesIO
from src.app import app

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_index_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Upload your JSON configuration file', response.data)

    def test_upload_valid_json(self):
        data = json.dumps({"debug": False})
        response = self.client.post(
            '/upload',
            data={'config_file': (BytesIO(data.encode('utf-8')), 'config.json')},
            content_type='multipart/form-data',
            follow_redirects=True  
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No vulnerabilities found', response.data)

    def test_upload_invalid_json(self):
        response = self.client.post(
            '/upload',
            data={'config_file': (BytesIO(b'not json'), 'config.json')},
            content_type='multipart/form-data',
            follow_redirects=True  
        )
        self.assertIn(b'Error processing file', response.data)

if __name__ == '__main__':
    unittest.main()
