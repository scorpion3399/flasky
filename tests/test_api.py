import unittest
import json
import re
from base64 import b64encode
from app import create_app, db
from app.models import User, Role, Post


class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def get_api_headers(self, username, password):
        return {
            'Authorization': 'Basic ' + b64encode(
                (username + ':' + password).encode('utf-8')).decode('utf-8'),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def test_404(self):
        response = self.client.get(
            '/wrong/url',
            headers=self.get_api_headers('username', 'password'))
        self.assertEqual(response.status_code, 404)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['error'], 'not found')

    def test_no_auth(self):
        response = self.client.get('/api/v1/posts/',
                                   content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_bad_auth(self):
        # add a user
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(username='john', password='cat', role=r)
        db.session.add(u)
        db.session.commit()

        # authenticate with bad password
        response = self.client.get(
            '/api/v1/posts/',
            headers=self.get_api_headers('john', 'dog'))
        self.assertEqual(response.status_code, 401)

    def test_token_auth(self):
        # add a user
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(username='john', password='cat', role=r)
        db.session.add(u)
        db.session.commit()

        # issue a request with a bad token
        response = self.client.get(
            '/api/v1/posts/',
            headers=self.get_api_headers('bad-token', ''))
        self.assertEqual(response.status_code, 401)

        # get a token
        response = self.client.post(
            '/api/v1/tokens/',
            headers=self.get_api_headers('john', 'cat'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertIsNotNone(json_response.get('token'))
        token = json_response['token']

        # issue a request with the token
        response = self.client.get(
            '/api/v1/posts/',
            headers=self.get_api_headers(token, ''))
        self.assertEqual(response.status_code, 200)

    def test_anonymous(self):
        response = self.client.get(
            '/api/v1/posts/',
            headers=self.get_api_headers('', ''))
        self.assertEqual(response.status_code, 401)

    def test_posts(self):
        # add a user
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(username='john', password='cat', role=r)
        db.session.add(u)
        db.session.commit()

        # write an empty post
        response = self.client.post(
            '/api/v1/posts/',
            headers=self.get_api_headers('john', 'cat'),
            data=json.dumps({'body': ''}))
        self.assertEqual(response.status_code, 400)

        # write a post
        response = self.client.post(
            '/api/v1/posts/',
            headers=self.get_api_headers('john', 'cat'),
            data=json.dumps({'body': 'body of the *blog* post'}))
        self.assertEqual(response.status_code, 201)
        url = response.headers.get('Location')
        self.assertIsNotNone(url)

        # get the new post
        response = self.client.get(
            url,
            headers=self.get_api_headers('john', 'cat'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual('http://localhost' + json_response['url'], url)
        self.assertEqual(json_response['body'], 'body of the *blog* post')
        self.assertEqual(json_response['body_html'],
                        '<p>body of the <em>blog</em> post</p>')
        json_post = json_response

        # get the post from the user
        response = self.client.get(
            '/api/v1/users/{}/posts/'.format(u.id),
            headers=self.get_api_headers('john', 'cat'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertIsNotNone(json_response.get('posts'))
        self.assertEqual(json_response.get('count', 0), 1)
        self.assertEqual(json_response['posts'][0], json_post)

        # edit post
        response = self.client.put(
            url,
            headers=self.get_api_headers('john', 'cat'),
            data=json.dumps({'body': 'updated body'}))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual('http://localhost' + json_response['url'], url)
        self.assertEqual(json_response['body'], 'updated body')
        self.assertEqual(json_response['body_html'], '<p>updated body</p>')

    def test_users(self):
        # add two users
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u1 = User(username='john', password='cat', role=r)
        u2 = User(username='susan', password='dog', role=r)
        # db.session.add_all([u1, u2])
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()

        # get users
        response = self.client.get(
            '/api/v1/users/{}'.format(u1.id),
            headers=self.get_api_headers('susan', 'dog'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['username'], 'john')
        response = self.client.get(
            '/api/v1/users/{}'.format(u2.id),
            headers=self.get_api_headers('susan', 'dog'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['username'], 'susan')
