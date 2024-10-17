'''
Interaction with Azure services
    Uses the MSAL library to support Azure and OAuth2.0

User to machine flow
    This flow is used when the user is able to interact with the application.

    1. The user goes to /api/login
    2. In response, the user receives a URL to the Azure login page
    3. The user goes to that login page and logs in interactively
    4. The user is presented with a JWT token

    This implementation doesn't use automatic redirects, as the API is
        not a web based application. It's supported for the user to use other
        apps, such as Postman or CURL to interact with the API.

Machine to machine flow
    This flow is for applications that run in the background without user
    interaction. For example, scripts that run on a schedule, or a chatbot.

    NOTE: THIS HAS NOT YET BEEN IMPLEMENTED

Check token validity on secured routes.
    This is to require a token for certain routes, and to check if the token is
    valid.

    NOTE: THIS HAS NOT YET BEEN IMPLEMENTED
'''

import msal
from flask import (
    Blueprint,
    request,
    jsonify,
)
from config_parse import config

SCOPES = ["User.Read"]
PORT = 5000


# Create the Azure Blueprint
azure_bp = Blueprint('azure', __name__)

# Initialize MSAL
msal_app = msal.ConfidentialClientApplication(
    config.azure_app,
    authority=f'https://login.microsoftonline.com/{config.azure_tenant}',
    client_credential=config.azure_secret
)


@azure_bp.route('/api/login')
def login():
    # Generate the authorization URL
    redirect_uri = (
        f"https://{request.host.split(':')[0]}:{PORT}{config.redirect_uri}"
    )

    try:
        auth_url = msal_app.get_authorization_request_url(
            scopes=SCOPES,
            redirect_uri=redirect_uri,
        )

    except Exception as e:
        print(e)
        return jsonify(
            {"failure": "Failed to generate authorization URL"}
        ), 500

    # Redirect the user to the Azure login page
    return jsonify(
        {
            "auth_url": auth_url
        }
    )


@azure_bp.route(config.redirect_uri)
def authorized():
    # Extract the authorization code from the query parameters
    code = request.args.get('code')

    if not code:
        return jsonify({"error": "Authorization code is missing"}), 400

    # Acquire the token by exchanging the authorization code
    redirect_uri = (
        f"https://{request.host.split(':')[0]}:{PORT}{config.redirect_uri}"
    )

    result = msal_app.acquire_token_by_authorization_code(
        code=code,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )

    if "access_token" in result:
        # Successfully acquired token
        return jsonify({"access_token": result["access_token"]})
    else:
        # Failed to acquire token
        return jsonify(
            {
                "error": "Failed to acquire token",
                "details": result.get('error_description')
            }
        )
