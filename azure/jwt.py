'''
JWT token management

When users authenticate, they are given a JWT token.
    This token is used to authenticate each API request.

API routes can be protected by requiring a valid JWT token.
    This is passed in the 'Authorization' header as 'Bearer' token

When a request is received, the JWT token needs to be validated.
    The 'validation_options' dictionary contains the validation options
    for the JWT token.

    The Signature is verified using the public key from the JWKS endpoint
        (Azure's public certificate).

    ISS is the token issuer (the application in Azure that issued the token).
        Azure supports version 1 and version 2 tokens, which depend on the
        application configuration. ISS validation is disabled to support
        either version.

    AUD is the audience (the application that the token is intended for).

The 'token_required' decorator is used to require a token for certain routes.
    Add this decorator to the route to require a token.

The 'validate_token' function is used to validate the token.
    It checks the token for expiration, audience, and issuer.
'''

import jwt
from jwt import PyJWKClient
import requests
from functools import wraps
from flask import request, jsonify

from config_parse import config


# Azure values needed for token validation
AZURE_TENANT = config.azure_tenant
AUTHORITY = f'https://login.microsoftonline.com/{AZURE_TENANT}'
OPENID_CONFIG_URL = f'{AUTHORITY}/v2.0/.well-known/openid-configuration'


# JWT validation options
#   ISS validation is disabled to support v1 and v2 tokens
validation_options = {
    'verify_signature': True,
    'verify_exp': True,
    'verify_nbf': True,
    'verify_iss': False,
    'verify_aud': True,
    'require': ['exp', 'iss', 'aud'],
}

# Get the JWKS URI from the OpenID configuration
response = requests.get(OPENID_CONFIG_URL)
response.raise_for_status()
openid_config = response.json()
jwks_uri = openid_config['jwks_uri']
jwks_client = PyJWKClient(jwks_uri)


def token_required(f):
    '''
    Decorator to require a token for certain routes
    '''

    @wraps(f)
    def decorated_function(*args, **kwargs):
        '''
        Check if the token is present and valid
        '''

        token = request.headers.get('Authorization')
        if not token:
            return jsonify(
                {
                    "result": "failure",
                    "message": "Token is missing"
                }
            ), 401

        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[len('Bearer '):]

        # Validate the token
        result = validate_token(token)

        if 'error' in result:
            return jsonify(
                {
                    "result": "failure",
                    "message": "Token is invalid",
                    "details": result['error']
                }
            ), 401

        return f(*args, **kwargs)
    return decorated_function


def validate_token(
    token
) -> dict:
    '''
    Function to validate the token
        Client adds the token to the Authorization header
        This function decodes the token, and confirms its validity

    JWKS - KSON Web Keys
        These are the IDP public keys used to verify the token signature
        When the IDP issues a token, it signs it with its private key
        The client can verify the token with the public key

    Args:
        token (str): JWT token

    Returns:
        dict: Decoded token or error message
    '''

    try:
        # Get the signing key from the token header
        signing_key = jwks_client.get_signing_key_from_jwt(token).key

        # Decode and validate the token
        decoded_token = jwt.decode(
            token,
            signing_key,
            algorithms=['RS256'],
            audience=config.azure_app,
            issuer=f'https://login.microsoftonline.com/{AZURE_TENANT}/v2.0',
            options=validation_options
        )

        return decoded_token

    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidAudienceError:
        return {'error': 'Invalid audience'}
    except jwt.InvalidIssuerError as e:
        print(e)
        return {'error': 'Invalid issuer'}
    except jwt.InvalidTokenError as e:
        return {'error': f'Invalid token: {str(e)}'}
