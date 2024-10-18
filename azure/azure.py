'''
Interaction with Azure services
    Uses the MSAL library to support Azure and OAuth2.0


User to machine flow
    This flow is used when the user is able to interact with the application.

    1. The user goes to /api/login
    2. In response, the user receives a URL to the Azure login page
    3. The user goes to that login page and logs in interactively
    4. Azure sends a code to the callback path (the redirect URI)
    5. The application exchanges the code for a JWT token
    6. The user is presented with the JWT token

    This implementation doesn't use automatic redirects, as the API is
        not a web based application. It's supported for the user to use other
        apps, such as Postman or CURL to interact with the API.


Machine to machine flow
    This flow is for applications that run in the background without user
    interaction. For example, scripts that run on a schedule, or a chatbot.

    NOTE: THIS HAS NOT YET BEEN IMPLEMENTED
'''

from flask import (
    Blueprint,
    request,
    jsonify,
)
import msal
import os

from config_parse import config


# Azure scopes (permissions) required by the application
#   This has to be right for JWT verification to work
SCOPES = [f"{config.azure_app}/.default"]

# Port to use for the redirect URI
#   This changes for prod and dev environments
PORT = int(os.getenv('web_port', 443))

# Create the blueprint for Flask
azure_bp = Blueprint('azure', __name__)

# Initialize MSAL object for OAuth2.0
msal_app = msal.ConfidentialClientApplication(
    config.azure_app,
    authority=f'https://login.microsoftonline.com/{config.azure_tenant}',
    client_credential=config.azure_secret
)


@azure_bp.route('/api/login')
def login() -> jsonify:
    '''
    Generate the authorization URL for the user
    This does not automatically redirect the user to the Azure login page.
        The user must manually go to the URL to login.
        This supports non-browser based applications (eg Postman, CURL)

    Returns:
        JSON: Authorization URL
    '''
    # Generate the redirecting URI (the callback URL)
    #   The port will change depending on the environment (dev/prod)
    redirect_uri = (
        f"https://{request.host.split(':')[0]}:{PORT}{config.redirect_uri}"
    )

    # Generate the authentication URL
    try:
        auth_url = msal_app.get_authorization_request_url(
            scopes=SCOPES,
            redirect_uri=redirect_uri,
        )

    except Exception as e:
        print(e)
        return jsonify(
            {
                "result": "failure",
                "message": "Failed to generate authorization URL"}
        ), 500

    # Return the authorization URL
    return jsonify(
        {
            "result": "success",
            "message": "Authorization URL generated",
            "auth_url": auth_url
        }
    )


@azure_bp.route(config.redirect_uri)
def authorized() -> jsonify:
    '''
    Authenticate the user, and get the token

    1. Extract the code from the query parameters
        This code is given to us from Azure
    2. Exchange the code for a token

    Returns:
        JSON: Token or error message
    '''

    # Extract the authorization code from the query parameters
    auth_code = request.args.get('code')

    if not auth_code:
        return jsonify(
            {
                "result": "failure",
                "message": "Authorization code is missing"
            }
        ), 400

    # Generate the redirecting URI (the callback URL)
    redirect_uri = (
        f"https://{request.host.split(':')[0]}:{PORT}{config.redirect_uri}"
    )

    # Present the auth code to Azure to get the token in return
    result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )

    # Present the user with the result
    if "access_token" in result:
        return jsonify(
            {
                "result": "success",
                "message": "Token acquired",
                "access_token": result["access_token"]
            }
        )

    else:
        return jsonify(
            {
                "result": "failure",
                "message": "Failed to acquire token",
                "details": result.get('error_description')
            }
        )
