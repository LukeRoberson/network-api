"""
Main module for starting the Network API.
    This is the entry point for the REST application.

Relies on the existance and correct formatting of config.yaml
    If this does not exist or is invalid, the web application will not start.
    This contains enough information to start the web application.
    More data is then read from an SQL database.

Usage:
    Run this module to start the web application.

Example:
    $ python main.py
"""

from flask import Flask
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint

import os
from config_parse import config
from colorama import Fore, Style

from azure.azure import azure_bp
from apiroutes import api_bp
from device import site_manager, device_manager
from vpn import vpn_manager


# Create a Flask web app
app = Flask(__name__)
CORS(
    app,
    resources={r"/api/*": {"origins": "http://localhost:5000"}},
    supports_credentials=True,
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-Filename",
        "Content-Disposition"
    ],
    expose_headers=["X-Filename", "Content-Disposition"]
)
app.secret_key = os.getenv('api_master_pw')

# Validate the configuration
if config.config_exists is False:
    print(
        Fore.RED,
        'Config file not found, exiting',
        Style.RESET_ALL
    )
    exit(1)

if config.config_valid is False:
    print(
        Fore.RED,
        'Config file is invalid, exiting',
        Style.RESET_ALL
    )
    exit(1)

# Load the API documentation
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yaml'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Network Management API"
    }
)
app.register_blueprint(
    swaggerui_blueprint,
    url_prefix=SWAGGER_URL
)

app.register_blueprint(api_bp)
app.register_blueprint(azure_bp)

site_manager.get_sites()
device_manager.get_devices()
vpn_manager.load_vpn()


if __name__ == "__main__":
    app.run(
        host=config.web_ip,
        port=config.web_port,
        debug=config.web_debug,
    )
