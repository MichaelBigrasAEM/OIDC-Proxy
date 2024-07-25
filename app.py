"""
    PIADHEvents - HTTP proxy for wrapping basic auth requests with openID connect authentication
    Copyright (C) 2024 Michael Bigras

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask
from flask import request
from flask import Response
from flask_httpauth import HTTPBasicAuth
import os
import time
import requests
import json

pass_hash = os.environ["pass_hash"]
auth = HTTPBasicAuth()

dist_serv = os.environ["dist_serv"]
dist_dest = os.environ["dist_dest"]

client_id = os.environ["client_id"]
client_secret = os.environ["client_secret"]

token = ''
token_expiration = 0

def get_token() -> str:
    global token
    global token_expiration
    if ((token_expiration - time.time()) > 5 * 50):
        return token

    endpoint = json.loads(requests.get(dist_serv + "/identity/.well-known/openid-configuration").content)
    token_endpoint = endpoint.get('token_endpoint')

    tokenInformation = requests.post(
        token_endpoint,
        data={'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials'})

    json_token = json.loads(tokenInformation.content)

    expiration = json_token.get('expires_in', None)
    if expiration is None:
        print(f'Failed to get token, check client id/secret: {token["error"]}')

    token_expiration = float(expiration) + time.time()
    token = json_token['access_token']
    return token

def sds_headers() -> dict[str, str]:
    headers = {"Content-type": "application/json"}
    headers["Authorization"] = "Bearer %s" % get_token()

    return headers

def send_data(json_data):
    headers = sds_headers()
    return requests.post(dist_serv + dist_dest, json=json_data, headers=headers)

app = Flask(__name__)

def on_json_loading_failed(e):
    raise ValueError from e

@auth.verify_password
def verify_password(username, password):
    if username == "pi" and password == pass_hash:
        return username

def recieve_packet(packet):
    data = packet.get_json()
    data["value"] = data["value"][0]
    data["asset"] = data["asset"][0]
    r = send_data(data)
    return r.text

@app.route("/", methods=['POST'])
@auth.login_required
def api_req():
    return recieve_packet(request)

if __name__ == '__main__':
    app.run()