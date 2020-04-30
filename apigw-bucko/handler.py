from datetime import datetime
from flywheel import Model, Field, Engine
from requests_oauthlib import OAuth2Session

from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth

import json
import os
import uuid
import base64
from http.cookies import SimpleCookie

# import logging
# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)


SESSION_COOKIE_KEY = "sessionid"

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

api_url = os.environ.get('api_url')
client_id = os.environ.get('client_id')
client_secret = os.environ.get('client_secret')  # TODO: put in SSM?

scope = 'openid offline'

secret_base64_encoded = base64.b64encode(f"{client_id}:{client_secret}".encode())
authorization_header = {"Authorization": f"Basic {secret_base64_encoded}"}

region = os.environ.get('AWS_REGION', 'eu-west-1')
sessions_tablename = os.environ.get('SESSIONS_TABLENAME', 'apigw-bucko-dev')

engine = Engine()
engine.connect_to_region(region)


# Set up our data model
class SessionObject(Model):

    __metadata__ = {
        '_name': sessions_tablename,
    }

    key = Field(hash_key=True)
    state = Field()
    token = Field()

    def __init__(self, key, state):
        self.key = key
        self.state = state


def wildcard(event, context):
    requestContext = event.get('requestContext')

    domain_name = requestContext.get('domainName')
    stage = requestContext.get('stage')
    gateway_path_url = requestContext.get('path')

    redirect_path = f"/{stage}/oauth2/code"

    if gateway_path_url == redirect_path:
        # redirect landing page
        print(f"--- redirect {gateway_path_url}")

        headers = event.get('headers', {})
        cookie = SimpleCookie()
        cookie.load(rawdata=headers.get('Cookie', ''))

        oauth_state = ""
        if SESSION_COOKIE_KEY in cookie:
            key = cookie.get(SESSION_COOKIE_KEY).value
            saved_session = engine.get(SessionObject, key=key)
            oauth_state = saved_session.state

        code = event.get('queryStringParameters', {}).get('code', '')

        print(f"oauth_state: {oauth_state}")
        print(f"code: {code}")

        response = {
            "statusCode": 200,
            "body": f"<html><body><h1>Hi - redirect landing! (from {domain_name})</h1></body></html>",
            "headers": {
                'Content-Type': 'text/html',
            }
        }
    else:
        # non-redirect
        print(f"--- non-redirect {gateway_path_url}")
        print(event)

        redirect_uri = f"https://{domain_name}{redirect_path}"
        authorization_base_url = f"{api_url}/tradeshift/auth/login"

        tradeshift = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
        authorization_url, oauth_state = tradeshift.authorization_url(authorization_base_url)

        session_uuid = str(uuid.uuid4())
        s = SessionObject(key=session_uuid, state=oauth_state)
        engine.save(s)

        headers = {
            "Location": authorization_url,
            "Set-Cookie": f"{SESSION_COOKIE_KEY}={session_uuid}; domain={domain_name}; secure; max-age=3600;",
        }
        headers.update(authorization_header)
        print(f"--- redirect to {authorization_url}")

        response = {
            "statusCode": 302,
            "headers": headers,
            "body": "",
        }

    return response


def root(event, context):
    requestContext = event.get('requestContext')
    domain_name = requestContext.get('domainName')
    authorization_base_url = f"{api_url}/tradeshift/auth/login"

    requestContext = event.get('requestContext')
    stage = requestContext.get('stage')
    domain_name = requestContext.get('domainName')
    redirect_uri = f"https://{domain_name}/{stage}/oauth2/code"

    tradeshift = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, oauth_state = tradeshift.authorization_url(authorization_base_url)

    session_uuid = str(uuid.uuid4())
    print(f"oauth_state = {oauth_state}")

    s = SessionObject(key=session_uuid, state=oauth_state)
    engine.save(s)

    #	response = {
    #		"statusCode": 200,
    #		"body": "<html><body><h1>Hi!</h1></body></html>",
    #		"headers": {
    #			'Content-Type': 'text/html',
    #		}
    #	}

    headers = {
        "Location": authorization_url,
        "Set-Cookie": f"{SESSION_COOKIE_KEY}={session_uuid}; domain={domain_name}; secure; max-age=3600;",
    }
    headers.update(authorization_header)

    response = {
        "statusCode": 302,
        "headers": headers,
        "body": "",
    }

    print(f"response: {response}")

    return response


# https://requests-oauthlib.readthedocs.io/en/latest/examples/real_world_example.html

def oauth2_code(event, context):

    token_url = f"{api_url}/tradeshift/auth/token"

    print(event)

    oauth_state = ''

    headers = event.get('headers', {})
    cookie = SimpleCookie()
    cookie.load(rawdata=headers.get('Cookie', ''))

    requestContext = event.get('requestContext')
    path = requestContext.get('path')
    domain_name = requestContext.get('domainName')
    callback_url = f"https://{domain_name}{path}"

    code = event.get('queryStringParameters', {}).get('code', '')

    if SESSION_COOKIE_KEY in cookie:
        key = cookie.get(SESSION_COOKIE_KEY).value
        saved_session = engine.get(SessionObject, key=key)
        oauth_state = saved_session.state

    tradeshift = f(client_id, state=oauth_state)

    print(f"code: {code}")
    print(f"oauth_state: {oauth_state}")
    print(f"callback_url: {callback_url}")
    print(f"token_url: {token_url}")

    auth = HTTPBasicAuth(client_id, client_secret)
    client = BackendApplicationClient(client_id=client_id)
    tradeshift = OAuth2Session(client=client)
    token = tradeshift.fetch_token(token_url=token_url, code=code, auth=auth)

    # https://ef0ymjxyc8.execute-api.eu-west-1.amazonaws.com/dev/oauth2/callback/
    # token = tradeshift.fetch_token(token_url, authorization_response=callback_url, client_secret=client_secret, headers=authorization_header) #, include_client_id=True, client_id=client_i<d<)

    body = {
        "message": "oauth2_code called",
        "input": event,
        "token": token
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    return response


def health(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    return response


def __main__():

    api_url = "https://api-sandbox.tradeshift.com"
    client_id = "HenningsSandboxSeller.zd4vt86hbj"
    client_secret = "527d038e-c726-44d0-b931-ca46c58c6314"

    authorization_base_url = f"{api_url}/tradeshift/auth/login"
    token_url = f"{api_url}/tradeshift/auth/token"
