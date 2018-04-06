import os
import json
import requests
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from flask import Flask, request, redirect, session, url_for


BASEPATH = '/flask/'
app = Flask(__name__)


class OIDCHandler:
    def __init__(self, client_secret='client_secrets.json'):
        with open(client_secret) as file:
            self.secrets = json.load(file)['web']


    def authorization_url(self):
        parts = list(urlparse(self.secrets['auth_uri']))
        params = {'response_type': 'code', 'client_id': self.secrets['client_id']}
        parts[4] = urlencode(params)
        return urlunparse(parts)


    def fetch_tokens(self, callback):
        params = parse_qs(urlparse(callback).query)

        payload = {
            'client_id': self.secrets['client_id'],
            'client_secret': self.secrets['client_secret'],
            'grant_type': 'authorization_code',
            'code': params['code'][0],
            'redirect_uri': self.secrets['redirect_uris'][0],
            'session_state': params['session_state'][0]
        }

        response = requests.post(self.secrets['token_uri'], data=payload, verify=False)
        return response.json()


@app.route('/callback', methods=["GET"])
def callback():
    oidch = OIDCHandler()
    tokens = oidch.fetch_tokens(request.url)
    session['authorized'] = True
    
    return redirect(BASEPATH)


@app.route('/')
def index():
    if not session.get('authorized'):
        oidch = OIDCHandler()
        return redirect(oidch.authorization_url())

    return app.send_static_file('index.html')


@app.route('/<path:path>')
def staticHost(path):
    if not session.get('authorized'):
        oidch = OIDCHandler()
        return redirect(oidch.authorization_url())

    try:
        return app.send_static_file(path)
    except NotFound as e:
        if path.endswith('/'):
            return app.send_static_file(path+'index.html')
        raise e


if __name__=='__main__':
    app.secret_key = os.urandom(24)
    app.run(debug=True)
