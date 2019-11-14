from datetime import datetime
from flywheel import Model, Field, Engine
from requests_oauthlib import OAuth2Session
import json
import os
import uuid
from http.cookies import SimpleCookie

SESSION_COOKIE_KEY = "sessionid"

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

api_url = os.environ.get('api_url')
client_id = os.environ.get('client_id')
client_secret = os.environ.get('client_secret')  # TODO: put in SSM?

region = os.environ.get('AWS_REGION')
sessions_tablename = os.environ.get('SESSIONS_TABLENAME')

engine = Engine()
engine.connect_to_region(region)


# Set up our data model
class SessionObject(Model):

    __metadata__ = {
        '_name': sessions_tablename,
    }

    key = Field(hash_key=True)
    state = Field()


def __init__(self, key, state):
    self.key = key
    self.state = state


def root(event, context):
    requestContext = event.get('requestContext')
    stage = requestContext.get('stage')
    domain_name = requestContext.get('domainName')
    authorization_base_url = f"{api_url}/tradeshift/auth/login?response_type=code&client_id={client_id}&redirect_uri=https://{domain_name}/{stage}/oauth2/callback/&scope=offline&state="

    tradeshift = OAuth2Session(client_id)
    authorization_url, oauth_state = tradeshift.authorization_url(authorization_base_url)

    session_uuid = str(uuid.uuid4())
    s = SessionObject(key=session_uuid, state=oauth_state)
    engine.save(s)

    #	response = {
    #		"statusCode": 200,
    #		"body": "<html><body><h1>Hi!</h1></body></html>",
    #		"headers": {
    #			'Content-Type': 'text/html',
    #		}
    #	}

    response = {
        "statusCode": 307,
        "headers": {
            "Location": authorization_url,
            "Set-Cookie": f"{SESSION_COOKIE_KEY}={session_uuid}; domain={domain_name}; secure; max-age=3600;"
        },
        "body": "",
    }
    return response


# https://requests-oauthlib.readthedocs.io/en/latest/examples/real_world_example.html

def oauth2_callback(event, context):

    token_url = f"{api_url}/external/auth/token"
    #
    # tradeshift = OAuth2Session(client_id, state=session['oauth_state'])
    # token = github.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)

    print(event)

    oauth_state = ''

    headers = event.get('headers', {})
    cookie = SimpleCookie()
    cookie.load(rawdata=headers.get('Cookie', ''))

    if SESSION_COOKIE_KEY in cookie:
        key = cookie.get(SESSION_COOKIE_KEY).value
        saved_session = engine.get(SessionObject, key=key)
        oauth_state = saved_session.state

    print("oauth_state")
    print(oauth_state)

    tradeshift = OAuth2Session(client_id, state=oauth_state)
    # token = tradeshift.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)



    body = {
        "message": "oauth2_callback called",
        "input": event
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
