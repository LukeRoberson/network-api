'''
Classes to simplify the creation of api routes in Flask.
    These are API routes, not web routes.
    Routes are registered as a blueprint

Success messages are in this JSON format:
    {
        "result": "Success",
        "message": "Some nice message"
    }

Failure messages are in this JSON format:
    {
        "result": "Failure",
        "message": "Some error message"
    }
'''

from flask import (
    Blueprint,
    request,
    jsonify,
    Response,
)

from flask.views import MethodView

import base64
from datetime import datetime
from colorama import Fore, Style
import os

from device import DeviceManager, SiteManager, device_manager, site_manager
from vpn import vpn_manager
from config_parse import AppSettings, config
from sql import SqlServer
from encryption import CryptoSecret

from pa_api import DeviceApi as PaDeviceApi
from junos_api import DeviceApi as JunosDeviceApi


# Define a blueprint for the web routes
api_bp = Blueprint('api', __name__)


class SqlView(MethodView):
    '''
    Sql class for managing SQL settings and connection

    Methods: POST

    Parameters:
        action (str): The action to perform.
            save: Save the SQL settings.
            test: Test the SQL settings.
    '''

    def post(
        self,
        config: AppSettings
    ) -> jsonify:
        '''
        Handle POST requests for the SQL settings.

        Args:
            config (AppSettings): The application settings object.

        Returns:
            jsonify: The result of the action.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # Save the SQL settings
        if parameters == 'save':
            # Handle sql_auth missing
            if 'sql_auth' not in request.form:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "SQL authentication type is missing"
                    }
                ), 200

            # Handle empty values
            if (
                request.form['sql_port'] == '' or
                request.form['sql_server'] == '' or
                request.form['sql_database'] == '' or
                request.form['sql_auth'] == ''
            ):
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "SQL settings can't be empty"
                    }
                ), 200

            # Check SQL auth vs username/password
            if request.form['sql_auth'] == 'SQL':
                if (
                    'sql_username' not in request.form or
                    'sql_password' not in request.form or
                    request.form['sql_username'] == '' or
                    request.form['sql_password'] == ''
                ):
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "SQL username/password can't be empty"
                        }
                    ), 200

            # Save username/password as variables if available
            if 'sql_username' in request.form:
                sql_username = request.form['sql_username']
            else:
                sql_username = ''

            if 'sql_password' in request.form:
                sql_password = request.form['sql_password']
            else:
                sql_password = ''

            # Check if the password has changed (don't double encrypt)
            if sql_password != config.sql_password and sql_password != '':
                print(
                    Fore.CYAN,
                    "Updating and encrypting password in config.yaml",
                    Style.RESET_ALL
                )

                # Encrypt the password
                with CryptoSecret() as encryptor:
                    encrypted = encryptor.encrypt(sql_password)
                    sql_password = encrypted[0].decode()
                    config.sql_salt = (
                        base64.urlsafe_b64encode(encrypted[1]).decode()
                    )

            else:
                print(
                    Fore.CYAN,
                    "Password hasn't changed, not encrypting or updating",
                    Style.RESET_ALL
                )

            # Attempt saving the settings to the config file
            try:
                config.sql_server = request.form['sql_server']
                config.sql_port = request.form['sql_port']
                config.sql_database = request.form['sql_database']
                config.sql_auth_type = request.form['sql_auth']
                config.sql_username = sql_username
                config.sql_password = sql_password
                config.write_config()

                # If it's all good, return a nice message
                return jsonify(
                    {
                        "result": "Success",
                        "message": "Settings saved"
                    }
                )

            # Return an error message if it failed
            except KeyError as e:
                print(Fore.RED, e, Style.RESET_ALL)
                return jsonify(
                    {
                        "result": "Failure",
                        "message": str(e)
                    }
                ), 500

        # Test the SQL settings
        elif parameters == 'test':
            # Connect to the SQL server and database
            with SqlServer(
                server=request.form['sql_server'],
                database=request.form['sql_database'],
                table='sites',
                config=config,
            ) as sql:
                result = sql.test_connection()

            # Success message if the connection was successful
            if result:
                return jsonify(
                    {
                        "result": "Success",
                        "message": (
                            f"Connected to {config.sql_server}\\"
                            f"{config.sql_database}"
                        )
                    }
                )

            # Failure message if the connection failed
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": (
                            f"Failed to connect to {config.sql_server}\\"
                            f"{config.sql_database}'s 'sites' table"
                        )
                    }
                )

        # Unknown or missing action
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 400


class WebView(MethodView):
    '''
    Web class For managing web settings

    Methods: POST

    Parameters:
        action (str): The action to perform.
            save: Save the web settings.
    '''

    def post(
        self,
        config: AppSettings,
    ) -> jsonify:
        '''
        Handle POST requests for the web settings.

        Args:
            config (AppSettings): The application settings object.

        Returns:
            jsonify: The result of the save operation.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # Save the web settings
        if parameters == 'save':
            # Attempt saving the settings to the config file
            try:
                config.web_ip = request.form['web_ip']
                config.web_port = request.form['web_port']

                # Check if the debug setting is on or off
                if request.form['web_debug'] == 'on':
                    config.web_debug = True
                else:
                    config.web_debug = False

                config.write_config()

                # If it's all good, return a nice message
                return jsonify(
                    {
                        "result": "Success",
                        "message": "Settings saved"
                    }
                )

            # Return an error message if it failed
            except KeyError as e:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": str(e)
                    }
                ), 500

        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 500


class SiteView(MethodView):
    '''
    Site class to manage sites in the database

    Methods: GET, POST

    GET Parameters:
        action (str): The action to perform.
            list: List all sites in the database.
            refresh: Refresh the site list.

    POST Parameters:
        action (str): The action to perform.
            add: Add a site to the database.
            delete: Delete a site from the database.
            update: Update a site in the database.
    '''

    def get(
        self,
        device_manager: DeviceManager,
        site_manager: SiteManager,
    ) -> jsonify:
        '''
        Get method to list sites in the database.

        Args:
            site_manager (SiteManager): The site manager object.

        Returns:
            jsonify: The list of sites in the database.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # List all sites in the database
        if parameters == 'list':
            # Create a list of site names
            site_list = []
            for site in site_manager.site_list:
                # Get a count of devices in the site
                device_counter = 0
                for device in device_manager.device_list:
                    if device.site == site.id:
                        device_counter += 1

                # Build the site info
                site_info = {
                    "site_id": site.id,
                    "site_name": site.name,
                    "device_count": device_counter,
                }

                # Add the site info to the list
                site_list.append(site_info)

            # Return the list of site names as JSON
            return jsonify(site_list)

        # Refresh the site list
        elif parameters == 'refresh':
            # Refresh the site and device list
            site_manager.get_sites()

            return jsonify(
                {
                    "result": "Success",
                    "message": "Site list refreshed"
                }
            )

        # Unknown or missing action
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 500

    def post(
        self,
        device_manager: DeviceManager,
        site_manager: SiteManager,
    ) -> jsonify:
        '''
        Post method to add a site to the database.

        Args:
            site_manager (SiteManager): The site manager object.

        Returns:
            jsonify: The result of the add operation.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # Add a site to the database
        if parameters == 'add':
            # Get the site name from the form
            site_name = request.form['siteName']

            # Add the site to the database
            new_site = site_manager.add_site(site_name)

            # Return a success message if the site was added
            if new_site is not None:
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Site '{site_name}' added successfully"
                    }
                )

            # Return a failure message if the site wasn't added
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Site '{site_name}' can't be added"
                    }
                ), 500

        # Delete a site from the database
        elif parameters == 'delete':
            # Get the site ID from the JSON request
            site_id = request.json['objectId']

            # Delete the site from the database
            result = site_manager.delete_site(site_id)

            # Return a success message if the site was deleted
            if result:
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Site '{site_id}' deleted"
                    }
                )

            # Return a failure message if the site wasn't deleted
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Site '{site_id}' can't be deleted"
                    }
                ), 500

        # Update a site in the database
        elif parameters == 'update':
            # Get the site name from the form
            site_name = request.form['siteEditName']

            # Update the site in the database
            updated_site = site_manager.update_site(
                id=request.form['siteEditId'],
                name=site_name
            )

            # Return a success message if the site was updated
            if updated_site:
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Site '{site_name}' updated successfully"
                    }
                )

            # Return a failure message if the site wasn't updated
            else:
                print(f"Site '{site_name}' can't be updated")
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Site '{site_name}' can't be updated"
                    }
                ), 500

        # Unknown or missing action
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 500


class DeviceView(MethodView):
    '''
    Device class to manage devices in the database.

    Methods: GET, POST

    GET Parameters:
        action (str): The action to perform.
            list: List all devices in the database.
            refresh: Refresh the device list.

    POST Parameters:
        action (str): The action to perform.
            add: Add a device to the database.
            delete: Delete a device from the database.
            update: Update a device in the database.
            download: Download the device configuration.
            reset: Reset the encryption for devices.
    '''

    def get(
        self,
        device_manager: DeviceManager,
        config: AppSettings,
    ) -> jsonify:
        '''
        Get method to list devices in the database.

        Args:
            device_manager (DeviceManager): The device manager object.

        Returns:
            jsonify: The list of devices in the database.
                device_id (str): The device ID.
                device_name (str): The device name.
                ha_state (str): The HA state of the device.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # List all devices in the database
        if parameters == 'list':
            # Create a list of device names
            device_list = []
            for device in device_manager.device_list:
                device_list.append(device.to_dict())

            # Get the 'id' parameter from the request if there is one
            device = request.args.get('id')

            # If there is no device parameter, return the device list
            if device is None:
                return jsonify(device_list)

            # If there is a device parameter, return the device entry
            device_entry = None
            for entry in device_list:
                if str(entry['device_id']) == device:
                    device_entry = entry

            if device_entry is not None:
                # Return the device entry as JSON
                return jsonify(device_entry)
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Device id not found"
                    }
                ), 500

        # List HA devices
        if parameters == 'ha':
            ha_list = []

            for pair in device_manager.ha_pairs:
                details = {}
                details['active'] = pair['active'].to_dict()['name']
                details['passive'] = pair['passive'].to_dict()['name']
                ha_list.append(details)

            return ha_list

        # Refresh the device list
        elif parameters == 'refresh':
            # Refresh the site and device list
            device_manager.get_devices()

            return jsonify(
                {
                    "result": "Success",
                    "message": "Device list refreshed"
                }
            )

        # Unknown or missing action
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 500

    def post(
        self,
        device_manager: DeviceManager,
        config: AppSettings,
    ) -> jsonify:
        '''
        Post method to add a device to the database.

        Args:
            device_manager (DeviceManager): The device manager object.

        Returns:
            jsonify: The result of the add operation.
        '''

        # Get the action parameter from the request
        parameters = request.args.get('action')

        # Add device to the database
        if parameters == 'add':
            # Get the device and the password from the form
            device_name = request.form['deviceName']
            password = request.form['apiPass']

            # Encrypt the password
            print(Fore.CYAN, "Encrypting password", Style.RESET_ALL)
            with CryptoSecret() as encryptor:
                encrypted = encryptor.encrypt(password)
                encrypted_key = encrypted[0].decode()
                salt = base64.urlsafe_b64encode(encrypted[1]).decode()

            # Add the device to the database
            print(Fore.CYAN, "Adding device to DB", Style.RESET_ALL)
            new_device = device_manager.add_device(
                name=device_name,
                hostname=request.form['hostName'],
                site=request.form['siteMember'],
                vendor=request.form['deviceVendor'],
                key=request.form['apiKey'],
                username=request.form['apiUser'],
                password=encrypted_key,
                salt=salt,
            )

            # Refresh the device list after adding a device
            print(Fore.CYAN, "Refreshing device list", Style.RESET_ALL)
            device_manager.get_devices()

            # Return a success message if the device was added
            if new_device:
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Device '{new_device.name}' added"
                    }
                )

            # Return a failure message if the device wasn't added
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Device '{device_name}' can't be added"
                    }
                ), 500

        # Delete a device from the database
        elif parameters == 'delete':
            # Get the device ID from the JSON request
            device_id = request.json['objectId']

            # Delete the device from the database
            result = device_manager.delete_device(device_id)

            # Refresh the device list after deleting a device
            print(Fore.CYAN, "Refreshing device list", Style.RESET_ALL)
            device_manager.get_devices()

            # Return a success message if the device was deleted
            if result:
                print(
                    Fore.GREEN,
                    f"Device '{device_id}' deleted",
                    Style.RESET_ALL
                )
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Device '{device_id}' deleted"
                    }
                )

            # Return a failure message if the device wasn't deleted
            else:
                print(
                    Fore.RED,
                    f"Device '{device_id}' can't be deleted",
                    Style.RESET_ALL
                )
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Device '{device_id}' can't be deleted"
                    }
                ), 500

        # Update a device in the database
        elif parameters == 'update':
            # Get the device name and password from the form
            device_name = request.form['deviceEditName']
            password = request.form['apiPassEdit']

            # Encrypt the password
            with CryptoSecret() as encryptor:
                encrypted = encryptor.encrypt(password)
                encrypted_key = encrypted[0].decode()
                salt = base64.urlsafe_b64encode(encrypted[1]).decode()

            # Update the device in the database
            updated_device = device_manager.update_device(
                id=request.form['deviceEditId'],
                name=device_name,
                hostname=request.form['hostNameEdit'],
                site=request.form['siteMemberEdit'],
                vendor=request.form['deviceVendorEdit'],
                key=request.form['apiKeyEdit'],
                username=request.form['apiUserEdit'],
                password=encrypted_key,
                salt=salt,
            )

            # Return a success message if the device was updated
            if updated_device:
                return jsonify(
                    {
                        "result": "Success",
                        "message": f"Device '{device_name}' updated"
                    }
                )

            # Return a failure message if the device wasn't updated
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": f"Device '{device_name}' can't be updated"
                    }
                ), 500

        # Download the device configuration
        elif parameters == 'download':
            # Get the device ID from the JSON request
            device_id = request.json['deviceId']
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=config.sql_server,
                database=config.sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device_id,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Parse the device details
            hostname = output[0][1]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            with CryptoSecret() as decryptor:
                # Decrypt the password
                real_pw = decryptor.decrypt(
                    secret=password,
                    salt=base64.urlsafe_b64decode(salt.encode())
                )
            api_pass = base64.b64encode(
                f'{username}:{real_pw}'.encode()
            ).decode()

            # Connect to the API
            if vendor == 'paloalto':
                my_device = PaDeviceApi(
                    hostname=hostname,
                    xml_key=api_pass,
                )

                # Download the device configuration, return as a file
                dev_config = my_device.get_config()
                filename = (
                    f"{hostname}_{datetime.now().strftime('%Y%m%d%H%M%S')}.xml"
                )
                print(f"downloading {filename}")
                response = Response(dev_config, mimetype='text/xml')
                response.headers['Content-Disposition'] = (
                    f'attachment; filename="{filename}"'
                )
                response.headers['X-Filename'] = filename
                return response

            elif vendor == 'juniper':
                my_device = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # Download the device configuration, return as a file
                dev_config = my_device.get_config()
                filename = (
                    f"{hostname}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
                )
                print(f"downloading {filename}")
                response = Response(dev_config, mimetype='text/plain')
                response.headers['Content-Disposition'] = (
                    f'attachment; filename="{filename}"'
                )
                response.headers['X-Filename'] = filename
                return response

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

        # Reset encryption for devices
        elif parameters == 'reset':
            # Get the master password from the request body
            master_password = request.json['password']

            print(f"Existing master password: {os.getenv('api_master_pw')}")
            print(f"New master password: {master_password}")

            # Loop through device list
            for device in device_manager.device_list:
                result = device.reset_password(password=master_password)
                if not result:
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "Failed resetting device password"
                        }
                    ), 500

            # Decrypt SQL password (from config)
            with CryptoSecret() as decryptor:
                real_pw = decryptor.decrypt(
                    secret=config.sql_password,
                    salt=base64.urlsafe_b64decode(
                        config.sql_salt.encode()
                    )
                )

            # Encrypt SQL password
            try:
                with CryptoSecret() as encryptor:
                    encrypted = encryptor.encrypt(
                        password=real_pw,
                        master_pw=master_password,
                    )
                    password_encoded = encrypted[0].decode()
                    salt_encoded = base64.urlsafe_b64encode(
                        encrypted[1]
                    ).decode()

            except Exception as e:
                print(
                    Fore.RED,
                    "Could not encrypt SQL password",
                    Style.RESET_ALL
                )
                print(e)

            # Update SQL PW in config object
            print(
                Fore.CYAN,
                "Updating SQL password in config.yaml",
                Style.RESET_ALL
            )
            config.sql_password = password_encoded
            config.sql_salt = salt_encoded
            config.write_config()

            # Update environnment variable
            os.environ['api_master_pw'] = master_password

            # Return a success message if the device was updated
            return jsonify(
                {
                    "result": "Success",
                    "message": "Master Password has been changed"
                }
            )

        # Unknown or missing action
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown action supplied"
                }
            ), 500


class ObjectsView(MethodView):
    '''
    Objects class to manage tags, addresses, etc

    Methods: GET, POST

    GET Parameters:
        object (str): The object type to get.
            tags: Get the tags for a device.
            addresses: Get the addresses for a device.
            address_groups: Get the address groups for a device.
            app_groups: Get the application groups for a device.
            services: Get the services for a device.
            service_groups: Get the service groups for a device.

    POST Parameters:
        object (str): The object type.
            tags: Get the tags for a device.
        action (str): The action to perform.
            create: Add a device to the database.
    '''

    def get(
        self,
        config: AppSettings,
    ) -> jsonify:
        '''
        Get method to get the tags for a device.

        Args:
            config (AppSettings): The application settings object.

        Returns:
            jsonify: The tags for the device.
        '''

        # Get the action parameter from the request
        object_type = request.args.get('object')

        # Get the tags for a device
        if object_type == 'tags':
            # Get the tags from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]

            # Create the device object
            my_device = PaDeviceApi(
                hostname=hostname,
                rest_key=token,
                version='v11.0'
            )

            # The tags from the device
            raw_tags = my_device.get_tags()

            # A cleaned up list of tags
            tag_list = []
            for tag in raw_tags:
                entry = {}
                entry["name"] = tag['@name']
                entry["description"] = tag.get(
                    'comments',
                    'No description available'
                )
                entry["colour"] = tag.get('color', 'no colour')
                tag_list.append(entry)

            # Sort the tags by name
            tag_list.sort(key=lambda x: x['name'])

            # Return the tags as JSON
            return jsonify(tag_list)

        # Get the addresses for a device
        elif object_type == 'addresses':
            # Get the address objects from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # The address objects from the device
                raw_addresses = device_api.get_addresses()

                # A cleaned up list of address objects
                address_list = []
                for address in raw_addresses:
                    entry = {}
                    entry["name"] = address['@name']

                    if 'ip-netmask' in address:
                        entry["addr"] = address['ip-netmask']
                    elif 'ip-range' in address:
                        entry["addr"] = address['ip-range']
                    elif 'fqdn' in address:
                        entry["addr"] = address['fqdn']
                    else:
                        entry["addr"] = 'No IP'
                        print(
                            Fore.RED,
                            f'No IP for object {entry['name']}',
                            Style.RESET_ALL
                        )

                    entry["description"] = address.get(
                        'description',
                        'No description',
                    )
                    entry["tag"] = address.get('tag', 'No tag')
                    address_list.append(entry)

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # The address objects from the device
                raw_addresses = device_api.get_addresses()
                if raw_addresses is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No addresses found"
                        }
                    ), 200

                # A cleaned up list of address objects
                address_list = []
                for address_book in raw_addresses:
                    for address in address_book['address']:
                        entry = {}
                        entry["name"] = address['name']
                        entry["addr"] = address.get(
                            'ip-prefix',
                            'No IP'
                        )
                        entry["description"] = address.get(
                            'description',
                            'No description',
                        )
                        address_list.append(entry)

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Sort the addresses by name
            address_list.sort(key=lambda x: x['name'])

            # Return the addresses as JSON
            return jsonify(address_list)

        # Get the address groups for a device
        elif object_type == 'address_groups':
            # Get the address group objects from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # The address groups from the device
                raw_address_groups = device_api.get_address_groups()

                # A cleaned up list of address groups
                address_group_list = []
                for address_group in raw_address_groups:
                    entry = {}
                    entry["name"] = address_group['@name']
                    entry["static"] = address_group.get('static', 'None')
                    entry["description"] = address_group.get(
                        'description',
                        'None'
                    )
                    entry["tag"] = address_group.get(
                        'tag',
                        {'member': ['No tags']}
                    )
                    address_group_list.append(entry)

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # The address groups from the device
                raw_address_groups = device_api.get_address_groups()

                # The address objects from the device
                raw_addresses = device_api.get_addresses()
                if raw_addresses is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No address groups found"
                        }
                    ), 200

                # A cleaned up list of address groups
                address_group_list = []
                for address_book in raw_addresses:
                    if 'address-set' in address_book:
                        for address in address_book['address-set']:
                            entry = {}
                            entry["name"] = address['name']
                            entry["static"] = address.get(
                                'address',
                                'None'
                            )
                            entry["description"] = address.get(
                                'description',
                                'None'
                            )
                            address_group_list.append(entry)

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Sort the address groups by name
            if address_group_list == []:
                return jsonify(
                    {
                        "result": "Success",
                        "message": "No address groups found"
                    }
                ), 200
            else:
                address_group_list.sort(key=lambda x: x['name'])

            # Return the address groups as JSON
            return jsonify(address_group_list)

        # Get the application groups for a device
        elif object_type == 'app_groups':
            # Get the application group objects from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # The application groups from the device
                raw_application_groups = device_api.get_application_groups()
                if raw_application_groups is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No application groups found"
                        }
                    ), 200

                # A cleaned up list of application groups
                application_group_list = []
                for application_group in raw_application_groups:
                    entry = {}
                    entry["name"] = application_group['@name']
                    entry["members"] = application_group.get(
                        'members',
                        'No members'
                    )
                    application_group_list.append(entry)

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # The application groups from the device
                raw_application_groups = device_api.get_application_groups()
                if raw_application_groups is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No application groups found"
                        }
                    ), 200

                # A cleaned up list of application groups
                application_group_list = []
                for application_group in raw_application_groups:
                    entry = {}
                    entry["name"] = application_group['name']
                    entry["members"] = application_group.get(
                        'applications',
                        'No members'
                    )
                    application_group_list.append(entry)

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Sort the application groups by name
            application_group_list.sort(key=lambda x: x['name'])

            # Return the application groups as JSON
            return jsonify(application_group_list)

        # Get the services for a device
        elif object_type == 'services':
            # Get the service objects from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # The service objects from the device
                raw_services = device_api.get_services()
                if raw_services is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No services found"
                        }
                    ), 200

                # A cleaned up list of service objects
                services_list = []
                for service in raw_services:
                    entry = {}
                    entry["name"] = service['@name']
                    entry["protocol"] = service['protocol']
                    entry["description"] = service.get(
                        'description',
                        'No description'
                    )
                    entry["tag"] = service.get('tag', 'No tag')
                    services_list.append(entry)

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # The service objects from the device
                raw_services = device_api.get_services()
                if raw_services is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No services found"
                        }
                    ), 200

                # A cleaned up list of service objects
                services_list = []
                for service in raw_services:
                    entry = {}
                    entry["name"] = service['name']
                    entry["protocol"] = service['protocol']
                    entry["description"] = service.get(
                        'description',
                        'No description'
                    )
                    entry["dest_port"] = service.get(
                        'destination-port',
                        'No port'
                    )
                    services_list.append(entry)

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Sort the service objects by name
            services_list.sort(key=lambda x: x['name'])

            # Return the service objects as JSON
            return jsonify(services_list)

        # Get the service groups for a device
        elif object_type == 'service_groups':
            # Get the service groups from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # The service groups from the device
                raw_service_groups = device_api.get_service_groups()
                if raw_service_groups is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No service groups found"
                        }
                    ), 200

                # A cleaned up list of service groups
                service_groups_list = []
                for service in raw_service_groups:
                    entry = {}
                    entry["name"] = service['@name']
                    entry["members"] = service.get('members', 'No members')
                    entry["tag"] = service.get('tag', 'No tags')
                    service_groups_list.append(entry)

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # The service groups from the device
                raw_service_groups = device_api.get_service_groups()
                if raw_service_groups is None:
                    return jsonify(
                        {
                            "result": "Success",
                            "message": "No service groups found"
                        }
                    ), 200

                # A cleaned up list of service groups
                service_groups_list = []
                for service in raw_service_groups:
                    entry = {}
                    entry["name"] = service['name']
                    entry["description"] = service.get(
                        'description',
                        'No description'
                    )
                    entry["members"] = service.get(
                        'application',
                        'No applications'
                    )
                    service_groups_list.append(entry)

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Sort the service groups by name
            service_groups_list.sort(key=lambda x: x['name'])

            # Return the service groups as JSON
            return jsonify(service_groups_list)

        # Unknown or missing object type
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown object type supplied"
                }
            ), 500

    def post(
        self,
        config: AppSettings,
    ) -> jsonify:
        '''
        Handle POST requests for the object settings.
        '''

        # Get the object type from the request
        object_type = request.args.get('object')

        # Get the action parameter from the request
        action = request.args.get('action')

        # Create a new tag
        if object_type == 'tags' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]

            # Create the device object
            device_api = PaDeviceApi(
                hostname=hostname,
                rest_key=token,
                version='v11.0'
            )

            data = request.json
            result = device_api.create_tag(
                name=data.get('name'),
                colour=data.get('colour'),
                comment=data.get('comment')
            )

            return jsonify(result)

        # Create a new address object
        if object_type == 'addresses' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                device_api.create_address(
                    name=request.json['name'],
                    address=request.json['address'],
                    description=request.json['description'],
                    tags=request.json['tag']
                )

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                device_api.create_address(
                    name=request.json['name'],
                    address=request.json['address'],
                    description=request.json['description'],
                )

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            return jsonify(
                {
                    "result": "Success",
                    "message": "Created address object"
                }
            ), 200

        # Create a new address group
        if object_type == 'address_groups' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # Get the members, which should be a list
                members = request.json['members']
                if type(members) is not list and ',' in members:
                    members = [member.strip() for member in members.split(',')]
                elif type(members) is not list:
                    members = [members]

                device_api.create_addr_group(
                    name=request.json['name'],
                    members=members,
                    description=request.json['description'],
                    tags=request.json['tag']
                )

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # Get the members, which should be a list
                members = request.json['members']
                if type(members) is not list and ',' in members:
                    members = [member.strip() for member in members.split(',')]
                elif type(members) is not list:
                    members = [members]

                # Create the address group
                device_api.create_addr_group(
                    name=request.json['name'],
                    members=members,
                )

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            return jsonify(
                {
                    "result": "Success",
                    "message": "Placeholder for creating address groups"
                }
            ), 200

        # Create a new application group
        if object_type == 'app_groups' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            # Get the members, which should be a list
            members = request.json['members']
            if type(members) is not list and ',' in members:
                members = [member.strip() for member in members.split(',')]
            elif type(members) is not list:
                members = [members]

            device_api.create_app_group(
                name=request.json['name'],
                members=members,
            )

            return jsonify(
                {
                    "result": "Success",
                    "message": "Placeholder for creating application groups"
                }
            ), 200

        # Create a new service object
        if object_type == 'services' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                device_api.create_service(
                    name=request.json['name'],
                    protocol=request.json['protocol'],
                    dest_port=request.json['port'],
                    description=request.json['description'],
                    tags=request.json['tag']
                )

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                device_api.create_service(
                    name=request.json['name'],
                    protocol=request.json['protocol'],
                    dest_port=request.json['port'],
                    description=request.json['description'],
                )

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            return jsonify(
                {
                    "result": "Success",
                    "message": "Placeholder for creating services"
                }
            ), 200

        # Create a new service group
        if object_type == 'service_groups' and action == 'create':
            # Get device information
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

            # Decrypt the password
            try:
                with CryptoSecret() as decryptor:
                    print(f"Decrypting password for device '{hostname}'.")
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )

            except Exception as e:
                print(
                    Fore.RED,
                    f"Could not decrypt password for device '{hostname}'.",
                    Style.RESET_ALL
                )
                print(e)
                real_pw = None

            # Create the device object
            if vendor == 'paloalto':
                device_api = PaDeviceApi(
                    hostname=hostname,
                    rest_key=token,
                    version='v11.0'
                )

                # Get the members, which should be a list
                members = request.json['members']
                if type(members) is not list and ',' in members:
                    members = [member.strip() for member in members.split(',')]
                elif type(members) is not list:
                    members = [members]

                # Create the service group
                device_api.create_service_group(
                    name=request.json['name'],
                    members=members,
                    tags=request.json['tag'],
                )

            elif vendor == 'juniper':
                device_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=real_pw,
                )

                # Check if description exists in the request
                description = request.json.get('description', 'no description')

                # Get the members, which should be a list
                members = request.json['members']
                if type(members) is not list and ',' in members:
                    members = [member.strip() for member in members.split(',')]
                elif type(members) is not list:
                    members = [members]

                # Create the service group
                device_api.create_service_group(
                    name=request.json['name'],
                    members=members,
                    description=description,
                )

            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown vendor"
                    }
                ), 500

            return jsonify(
                {
                    "result": "Success",
                    "message": "Placeholder for creating service groups"
                }
            ), 200

        # Unknown or missing action
        return jsonify(
            {
                "result": "Failure",
                "message": "Unknown action supplied"
            }
        ), 500


class PolicyView(MethodView):
    '''
    Class to manage policies for a device.

    Methods: GET

    Parameters:
        type (str): The type of policy to get.
            nat: Get the NAT policies for a device.
            security: Get the security policies for a device.
            qos: Get the QoS policies for a device.
    '''

    def get(
        self,
        config: AppSettings,
    ) -> jsonify:
        '''
        Get method for device policies

        Args:
            config (AppSettings): The application settings object.

        Returns:
            jsonify: The NAT policies for the device.
        '''

        # Get the action parameter from the request
        policy_type = request.args.get('type')

        # Get the NAT policies for a device
        if policy_type == 'nat':
            # Get the NAT policies from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]

            # Create the device object
            device_api = PaDeviceApi(
                hostname=hostname,
                rest_key=token,
                version='v11.0'
            )

            # The NAT policies from the device
            raw_nat = device_api.get_nat_policies()

            # A cleaned up list of NAT policies
            nat_list = []
            for policy in raw_nat:
                entry = {}
                entry["name"] = policy['@name']
                entry["source_trans"] = policy.get(
                    'source-translation',
                    'None'
                )
                entry["dest_trans"] = policy.get(
                    'destination-translation',
                    'None'
                )
                entry["to"] = policy.get('to', 'None')
                entry["from"] = policy.get('from', 'None')
                entry["source"] = policy.get('source', 'None')
                entry["destination"] = policy.get('destination', 'None')
                entry["service"] = policy.get('service', 'None')
                entry["tag"] = policy.get('tag', 'None')
                entry["tag_group"] = policy.get('group-tag', 'None')
                entry["description"] = policy.get('description', 'None')
                entry["disabled"] = policy.get('disabled', 'no')
                nat_list.append(entry)

            # Return the NAT policies as JSON
            return jsonify(nat_list)

        # Get the security policies for a device
        elif policy_type == 'security':
            # Get the security policies from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]

            # Create the device object
            device_api = PaDeviceApi(
                hostname=hostname,
                rest_key=token,
                version='v11.0'
            )

            # The security policies from the device
            raw_security = device_api.get_security_policies()

            # A cleaned up list of security policies
            security_list = []
            for rule in raw_security:
                entry = {}
                entry["name"] = rule['@name']
                entry["to"] = rule.get('to', 'None')
                entry["from"] = rule.get('from', 'None')
                entry["source"] = rule.get('source', 'None')
                entry["destination"] = rule.get('destination', 'None')
                entry["source_user"] = rule.get('source-user', 'None')
                entry["category"] = rule.get('category', 'None')
                entry["application"] = rule.get('application', 'None')
                entry["service"] = rule.get('service', 'None')
                entry["action"] = rule.get('action', 'None')
                entry["type"] = rule.get('rule-tupe', 'None')
                entry["log"] = rule.get('log-setting', 'None')
                entry["log_start"] = rule.get('log-start', 'no')
                entry["log_end"] = rule.get('log-end', 'no')
                entry["disabled"] = rule.get('disabled', 'no')
                entry["tag"] = rule.get('tag', 'None')
                entry["tag_group"] = rule.get('group-tag', 'None')
                entry["description"] = rule.get('description', 'None')
                security_list.append(entry)

            # Return the security policies as JSON
            return jsonify(security_list)

        # Get the QoS policies for a device
        elif policy_type == 'qos':
            # Get the QoS policies from the device
            device = request.args.get('id')
            sql_server = config.sql_server
            sql_database = config.sql_database
            table = 'devices'

            # Read the device details from the database
            with SqlServer(
                server=sql_server,
                database=sql_database,
                table=table,
                config=config,
            ) as sql:
                output = sql.read(
                    field='id',
                    value=device,
                )

            # Return a failure message if the database read failed
            if not output:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Problems reading from the database"
                    }
                ), 500

            # Extract the details from the SQL output
            hostname = output[0][1]
            token = output[0][9]

            # Create the device object
            device_api = PaDeviceApi(
                hostname=hostname,
                rest_key=token,
                version='v11.0'
            )

            # The QoS policies from the device
            raw_qos = device_api.get_qos_policies()

            # A cleaned up list of security policies
            security_list = []
            for rule in raw_qos:
                entry = {}
                entry["name"] = rule['@name']
                entry["to"] = rule.get('to', 'None')
                entry["from"] = rule.get('from', 'None')
                entry["source"] = rule.get('source', 'None')
                entry["destination"] = rule.get('destination', 'None')
                entry["source_user"] = rule.get('source-user', 'None')
                entry["category"] = rule.get('category', 'None')
                entry["application"] = rule.get('application', 'None')
                entry["service"] = rule.get('service', 'None')
                entry["action"] = rule.get('action', 'None')
                entry["dscp"] = rule.get('dscp-tos', 'None')
                entry["tag"] = rule.get('tag', 'None')
                entry["tag_group"] = rule.get('group-tag', 'None')
                entry["description"] = rule.get('description', 'None')
                security_list.append(entry)

            # Return the security policies as JSON
            return jsonify(security_list)

        # Unknown or missing policy type
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown policy type supplied"
                }
            ), 500


class VpnView(MethodView):
    '''
    Class to get and manage VPN tunnels for a device.
        Includes GP and IPSec

    Methods: GET, POST

    Parameters:
        type (str): The type of VPN to get.
            gp: Get the Global Protect sessions for a device.
            ipsec: Get the IPSec tunnels for a device.
    '''

    def get(
        self,
        config: AppSettings,
        device_manager: DeviceManager,
    ) -> jsonify:
        '''
        Get method for VPNs on a device.

        Args:
            config (AppSettings): The application settings object.

        Returns:
            jsonify: The Global Protect sessions for the device.
        '''

        # Get parameters from the request
        vpn_type = request.args.get('type')
        action = request.args.get('action')
        id = request.args.get('id')

        # Get the Global Protect sessions for a device
        if vpn_type == 'gp':
            # Get the Global Protect sessions from the device
            device_id = request.args.get('id')
            for device in device_manager.device_list:
                if str(device.id) == device_id:
                    hostname = device.hostname
                    username = device.username
                    password = device.decrypted_pw
                    break

            api_pass = base64.b64encode(
                f'{username}:{password}'.encode()
            ).decode()

            # Create the device object
            device_api = PaDeviceApi(
                hostname=hostname,
                xml_key=api_pass,
            )

            # The Global Protect sessions from the device
            raw_gp_sessions = device_api.get_gp_sessions()

            # A cleaned up list of Global Protect sessions
            session_list = []
            for gp_session in raw_gp_sessions:
                entry = {}
                entry["name"] = gp_session.get('username', 'None')
                entry["username"] = gp_session.get('primary-username', 'None')
                entry["region"] = gp_session.get('source-region', 'None')
                entry["computer"] = gp_session.get('computer', 'None')
                entry["client"] = gp_session.get('client', 'None')
                entry["vpn_type"] = gp_session.get('vpn-type', 'None')
                entry["host"] = gp_session.get('host-id', 'None')
                entry["version"] = gp_session.get('app-version', 'None')
                entry["inside_ip"] = gp_session.get('virtual-ip', 'None')
                entry["outside_ip"] = gp_session.get('public-ip', 'None')
                entry["tunnel_type"] = gp_session.get('tunnel-type', 'None')
                entry["login"] = gp_session.get('login-time', 'None')
                session_list.append(entry)

            # Sort the security policies by name
            session_list.sort(key=lambda x: x['name'])

            # Return the security policies as JSON
            return jsonify(session_list)

        # If IPSec tunnels are requested
        elif vpn_type == 'ipsec':
            # If there is no action, return the list of managed VPN tunnels
            if action is None:
                vpn_list = []

                for vpn in vpn_manager:
                    # Get device names, if they exist
                    a_name = device_manager.id_to_name(vpn.a_device)
                    if a_name is not None and '.' in a_name:
                        a_name = a_name.split('.')[0]

                    b_name = device_manager.id_to_name(vpn.b_device)
                    if b_name is not None and '.' in b_name:
                        b_name = b_name.split('.')[0]

                    a_fw_name = device_manager.id_to_name(vpn.a_fw)
                    if a_fw_name is not None and '.' in a_fw_name:
                        a_fw_name = a_fw_name.split('.')[0]

                    b_fw_name = device_manager.id_to_name(vpn.b_fw)
                    if b_fw_name is not None and '.' in b_fw_name:
                        b_fw_name = b_fw_name.split('.')[0]

                    # Build dictionary of details
                    entry = {}
                    entry["name"] = vpn.name

                    a_endpoint = {}
                    a_endpoint["id"] = vpn.a_device
                    a_endpoint["name"] = a_name
                    a_endpoint["destination"] = vpn.a_dest
                    a_endpoint["fw_id"] = vpn.a_fw
                    a_endpoint["fw_name"] = a_fw_name
                    a_endpoint["nat_inside"] = vpn.a_inside_nat
                    a_endpoint["nat_outside"] = vpn.a_outside_nat
                    entry["a_endpoint"] = a_endpoint

                    b_endpoint = {}
                    b_endpoint['type'] = vpn.b_type
                    b_endpoint['id'] = vpn.b_device
                    b_endpoint['name'] = b_name
                    b_endpoint['cloud_ip'] = vpn.b_cloud
                    b_endpoint['destination'] = vpn.b_dest
                    b_endpoint['fw_id'] = vpn.b_fw
                    b_endpoint['fw_name'] = b_fw_name
                    b_endpoint['nat_inside'] = vpn.b_inside_nat
                    b_endpoint['nat_outside'] = vpn.b_outside_nat
                    entry['b_endpoint'] = b_endpoint

                    vpn_list.append(entry)

                # Return the VPN tunnels as JSON
                return jsonify(vpn_list)

            # If the action is 'status', return the status of the VPN tunnel
            elif action == 'status':
                # Check that an ID was supplied
                if id is None:
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": (
                                "A VPN ID must be supplied if the "
                                "VPN status is requested"
                            )
                        }
                    ), 500

                # Get the device from device manager
                vpn_device = None
                for device in device_manager:
                    if str(device.id) == str(id):
                        vpn_device = device
                        break

                if vpn_device is None:
                    print('VPN ID not found')
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "VPN ID not found"
                        }
                    ), 500

                # Get device details from SQL
                table = 'devices'
                with SqlServer(
                    server=config.sql_server,
                    database=config.sql_database,
                    table=table,
                    config=config,
                ) as sql:
                    output = sql.read(
                        field='id',
                        value=id,
                    )

                # Return a failure message if the database read failed
                if not output:
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "Problems reading from the database"
                        }
                    ), 500

                # Parse the device details
                hostname = output[0][1]
                vendor = output[0][3]
                username = output[0][6]
                password = output[0][7]
                salt = output[0][8]

                # Decrypt the password
                with CryptoSecret() as decryptor:
                    # Decrypt the password
                    real_pw = decryptor.decrypt(
                        secret=password,
                        salt=base64.urlsafe_b64decode(salt.encode())
                    )
                api_pass = base64.b64encode(
                    f'{username}:{real_pw}'.encode()
                ).decode()

                # Select the right vendor
                if vendor == 'paloalto':
                    device_api = PaDeviceApi(
                        hostname=hostname,
                        xml_key=api_pass,
                    )

                elif vendor == 'juniper':
                    device_api = JunosDeviceApi(
                        hostname=hostname,
                        username=username,
                        password=real_pw,
                    )

                else:
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "Unknown vendor"
                        }
                    ), 500

                # Get the VPN status
                vpn_status = device_api.get_vpn_status()
                if vpn_status:
                    tunnel_list = []
                    for tunnel in vpn_status:
                        entry = {}

                        entry['ike_name'] = tunnel.get('ike-name', 'None')
                        entry['ike_status'] = tunnel.get('ike_state', 'None')
                        entry['local_ip'] = tunnel.get('localip', 'None')

                        if 'ipsec-name' in tunnel:
                            entry['ipsec_name'] = tunnel.get('ipsec-name')
                        elif 'name' in tunnel:
                            entry['ipsec_name'] = tunnel.get('name')
                        else:
                            entry['ipsec_name'] = 'None'

                        if 'peerip' in tunnel:
                            entry['destination'] = tunnel.get('peerip')
                        elif 'ike_address' in tunnel:
                            entry['destination'] = tunnel.get('ike_address')
                        else:
                            entry['destination'] = 'None'

                        if 'ipsec_state' in tunnel:
                            entry['ipsec_status'] = tunnel.get('ipsec_state')
                        elif 'state' in tunnel:
                            entry['ipsec_status'] = tunnel.get('state')
                        else:
                            entry['ipsec_status'] = 'None'

                        if entry['ipsec_status'] == 'active':
                            entry['ipsec_status'] = 'up'

                        if 'outer-if' in tunnel:
                            entry['physical_if'] = tunnel.get('outer-if')
                        elif 'ike_interface' in tunnel:
                            entry['physical_if'] = tunnel.get('ike_interface')
                        else:
                            entry['physical_if'] = 'None'

                        if 'inner-if' in tunnel:
                            entry['tunnel_if'] = tunnel.get('inner-if')
                        elif 'ipsec_interface' in tunnel:
                            entry['tunnel_if'] = tunnel.get('ipsec_interface')
                        else:
                            entry['tunnel_if'] = 'None'

                        tunnel_list.append(entry)

                    return jsonify(tunnel_list)

                else:
                    return jsonify(
                        {
                            "result": "Failure",
                            "message": "VPN status not found"
                        }
                    ), 500

            # Unknown action
            else:
                return jsonify(
                    {
                        "result": "Failure",
                        "message": "Unknown action supplied"
                    }
                ), 500

        # Unknown or missing policy type
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Unknown policy type supplied"
                }
            ), 500

    def post(
        self,
        config: AppSettings,
        device_manager: DeviceManager,
    ) -> jsonify:
        '''
        Handle POST requests for VPN settings.

        Parameters:
            type (str): The type of VPN to update.
                ipsec: Update the IPSec tunnels for a device

            action (str): The action to take.
                add: Add a new VPN definition
        '''

        # Get the action parameter from the request
        action = request.args.get('action')

        # Get the type of VPN to update
        vpn_type = request.args.get('type')

        # Add a VPN definition
        if action == 'add' and vpn_type == 'ipsec':
            # Get the body of the request
            data = request.json

            vpn_manager.add_vpn(data)

            # Success message
            return jsonify(
                {
                    "result": "Success",
                    "message": "Managed VPN added"
                }
            ), 200

        # Unknown or missing action
        return jsonify(
            {
                "result": "Failure",
                "message": "Unknown VPN action or type"
            }
        ), 500

    def delete(
        self,
        config: AppSettings,
        device_manager: DeviceManager,
    ):
        '''
        Handle DELETE requests for VPN settings.

        Parameters:
            config (AppSettings): The application settings object.
            device_manager (DeviceManager): The device manager object.
        '''

        # Get the body of the request
        data = request.json
        result = vpn_manager.delete_vpn(data)

        # Return the result
        if result:
            return jsonify(
                {
                    "result": "Success",
                    "message": "Managed VPN deleted"
                }
            ), 200
        else:
            return jsonify(
                {
                    "result": "Failure",
                    "message": "Managed VPN not found"
                }
            ), 500


# Register sql view
api_bp.add_url_rule(
    '/api/sql',
    view_func=SqlView.as_view('sql'),
    defaults={'config': config}
)

# Register web view
api_bp.add_url_rule(
    '/api/web',
    view_func=WebView.as_view('web'),
    defaults={'config': config}
)

# Register site view
api_bp.add_url_rule(
    '/api/site',
    view_func=SiteView.as_view('site'),
    defaults={
        'device_manager': device_manager,
        'site_manager': site_manager
    }
)

# Register device view
api_bp.add_url_rule(
    '/api/device',
    view_func=DeviceView.as_view('device'),
    defaults={
        'device_manager': device_manager,
        'config': config,
    }
)

# Register objects view
api_bp.add_url_rule(
    '/api/objects',
    view_func=ObjectsView.as_view('objects'),
    defaults={'config': config}
)

# Register policies view
api_bp.add_url_rule(
    '/api/policies',
    view_func=PolicyView.as_view('policies'),
    defaults={'config': config}
)

# Register VPN view
api_bp.add_url_rule(
    '/api/vpn',
    view_func=VpnView.as_view('vpn'),
    defaults={'config': config, 'device_manager': device_manager}
)
