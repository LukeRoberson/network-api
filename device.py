'''
Classes to manage sites and devices
Tracks each of these objects, and contains methods to manage them
'''

from sql import SqlServer
from config_parse import AppSettings, config
from encryption import CryptoSecret

from pa_api import DeviceApi as PaDeviceApi
from junos_api import DeviceApi as JunosDeviceApi

from colorama import Fore, Style
import concurrent.futures
import uuid
import base64
import os


class Site:
    '''
    Site class
    Contains the name and id of a site
    This will likely be instantiated multiple times, and stored in a list

    Methods:
        __init__: Constructor for Site class
        __str__: String representation of the site
        __len__: Returns the number of devices assigned to the site
        device_count: Returns the number of devices assigned to the site
    '''

    def __init__(
        self,
        name: str,
        id: uuid,
    ) -> None:
        '''
        Constructor for Site class
        Gets the name and id of the site

        Args:
            name (str): Name of the site
            id (uuid): Unique identifier for the site
        '''

        self.name = name
        self.id = id

        # Devices assigned to the site
        self.devices = []

    def __str__(
        self
    ) -> str:
        '''
        String representation of the site
        Returns a friendly string of the site

        Returns:
            str: Friendly string of the site
        '''

        return self.name

    def __len__(
        self
    ) -> int:
        '''
        Returns the number of devices assigned to the site

        Returns:
            int: Number of devices assigned to the site
        '''

        return len(self.devices)

    @property
    def device_count(
        self
    ) -> int:
        '''
        Returns the number of devices assigned to the site
        Exposed as a property so it can be accessed directly

        Returns:
            int: Number of devices assigned to the site
        '''

        return self.__len__()


class Device:
    '''
    Device class
    Contains device details
    This will likely be instantiated multiple times, and stored in a list

    Methods:
        __init__: Constructor for Device class
        __str__: String representation of the device
    '''

    def __init__(
        self,
        id: uuid,
        hostname: str,
        site: uuid,
        key: str,
        username: str,
        password: str,
        salt: str,
        vendor: str,
        full_vendor: str = '',
        name: str = '',
        serial: str = '',
        ha_partner_serial: str = '',
        config: AppSettings = None,
    ) -> None:
        '''
        Constructor for Device class

        Args:
            id (uuid): Unique identifier for the site
            hostname (str): Hostname of the device
            site (uuid): Site identifier
            key (str): REST API key for the device
            username (str): Username for the device (XML API)
            password (str): Encrypted password for the device (XML API)
            salt (str): Salt for the encrypted (XML API)
            vendor (str): Vendor of the device (short form in DB)
            full_vendor (str): Full vendor name (for display)
            name (str): Friendly name of the device
            serial (str): Serial number of the device
            ha_partner_serial (str): Serial number of the HA partner
        '''

        # Configuration
        self.config = config

        # Device details
        self.name = name
        self.id = id
        self.hostname = hostname
        self.site = site
        self.vendor = vendor
        self.full_vendor = full_vendor
        self.serial = serial
        self.ha_partner_serial = ha_partner_serial
        self.model = None
        self.version = None

        # API details
        self.key = key
        self.username = username
        self.password = password
        self.decrypted_pw = None
        self.salt = salt

        # HA Details
        self.ha_enabled = None
        self.ha_local_state = None
        self.ha_peer_state = None
        self.ha_peer_serial = None

        # Track the site name
        self.site_name = ''

    def __str__(
        self
    ) -> str:
        '''
        String representation of the device
        Returns a friendly string of the device

        Returns:
            str: Friendly string of the device
        '''

        return self.name

    def get_details(
        self,
    ) -> None:
        '''
        Get the device details from the API
        Update the device object
        '''

        settings = AppSettings()
        table = 'devices'

        with SqlServer(
            server=settings.sql_server,
            database=settings.sql_database,
            table=table,
            config=self.config
        ) as sql:
            output = sql.read(
                field='id',
                value=self.id,
            )

        if output:
            # Extract the details from the SQL output
            hostname = output[0][1]
            vendor = output[0][3]
            username = output[0][6]
            password = output[0][7]
            salt = output[0][8]

        else:
            print(
                Fore.RED,
                f"Could not read device details for device '{self.hostname}'.",
                Style.RESET_ALL
            )
            return

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

        # If the password was decrypted, continue getting info
        if real_pw:
            # Encode the username and password for the API
            api_pass = base64.b64encode(
                f'{username}:{real_pw}'.encode()
            ).decode()
            self.decrypted_pw = real_pw

            # Create the device API object
            if vendor == 'paloalto':
                dev_api = PaDeviceApi(
                    hostname=hostname,
                    xml_key=api_pass,
                )
            elif vendor == 'juniper':
                dev_api = JunosDeviceApi(
                    hostname=hostname,
                    username=username,
                    password=self.decrypted_pw,
                )

            # Get device details
            details = dev_api.get_device()
            ha = dev_api.get_ha()

            # Update the device object
            #   Integers are returned if the API call fails
            if type(details) is not int:
                self.model = details[0]
                self.serial = details[1]
                self.version = details[2]

            # Update the HA details
            if type(ha) is not int:
                self.ha_enabled = ha[0]

                if self.ha_enabled:
                    self.ha_local_state = ha[1]
                    self.ha_peer_state = ha[2]
                    self.ha_peer_serial = ha[3]

        # If the password was not decrypted, return
        else:
            print(
                Fore.RED,
                f"Error decrypting password for device '{hostname}'.",
                Style.RESET_ALL
            )
            details = None

        # Update the DB
        if type(details) is not int or type(ha) is not int:
            self._update_db()

    def reset_password(
        self,
        password: str,
    ) -> bool:
        '''
        Reencrypt the password for the device
            This is done when the master password is changed

        Args:
            password (str): The new master password
                This is used to encrypt the password in the DB

        Returns:
            bool: True if successful, otherwise False
        '''

        # Update details
        self.get_details()

        # Encrypt with new master password
        print(f"Encrypting password for device '{self.name}'")
        print(f"Decrypted PW: {self.decrypted_pw}")
        print(f'old master pw: {os.getenv('api_master_pw')}')
        print(f'new master pw: {password}')

        try:
            with CryptoSecret() as encryptor:
                encrypted = encryptor.encrypt(
                    password=self.decrypted_pw,
                    master_pw=password,
                )
                self.password_encoded = encrypted[0].decode()
                self.salt_encoded = base64.urlsafe_b64encode(
                    encrypted[1]
                ).decode()

        except Exception as e:
            print(
                Fore.RED,
                f"Could not encrypt password for device '{self.name}'.",
                Style.RESET_ALL
            )
            print(e)
            return False

        # Update the database with password and salt
        with SqlServer(
            server=config.sql_server,
            database=config.sql_database,
            table='devices',
            config=config,
        ) as sql:
            try:
                sql.update(
                    field='id',
                    value=self.id,
                    body={
                        'friendly_name': self.name,
                        'name': self.hostname,
                        'site': self.site,
                        'token': self.key,
                        'username': self.username,
                        'secret': self.password_encoded,
                        'salt': self.salt_encoded,
                    }
                )

            except Exception as e:
                print(
                    Fore.RED,
                    "Could not update device in the database.",
                    Style.RESET_ALL,
                    e,
                )
                return False

        print(
            Fore.GREEN,
            f'Resetting password for device {self.name}',
            f'Encrypted PW: {self.password_encoded}',
            f'Salt: {self.salt_encoded}',
            Style.RESET_ALL
        )
        return True

    def _update_db(
        self,
    ) -> None:
        '''
        Update the device details in the database
        '''

        # Update the device in the database, based on the ID
        settings = AppSettings()
        table = 'devices'

        with SqlServer(
            server=settings.sql_server,
            database=settings.sql_database,
            table=table,
            config=self.config,
        ) as sql:
            result = sql.update(
                field='id',
                value=self.id,
                body={
                    'name': self.hostname,
                    'site': self.site,
                    'serial': self.serial,
                    'ha_partner': self.ha_peer_serial,
                }
            )

        if not result:
            print(
                Fore.RED,
                f"Could not update device details for '{self.hostname}'",
                Style.RESET_ALL
            )

    def to_dict(
        self,
    ) -> dict:
        '''
        Convert the device object to a dictionary

        Returns:
            dict: A dictionary of device details
        '''

        return {
            'id': self.id,
            'hostname': self.hostname,
            'site': self.site,
            'key': self.key,
            'username': self.username,
            'password': self.password,
            'salt': self.salt,
            'name': self.name,
            'vendor': self.vendor,
            'full_vendor': self.full_vendor,
            'serial': self.serial,
            'ha_partner_serial': self.ha_partner_serial,
            'model': self.model,
            'version': self.version,
            'ha_enabled': self.ha_enabled,
            'ha_local_state': self.ha_local_state,
            'ha_peer_state': self.ha_peer_state,
            'ha_peer_serial': self.ha_peer_serial,
            'site_name': self.site_name,
        }


class SiteManager():
    '''
    A class to manage all sites
    Stores all sites in a list (from the database)
    Adds and removes sites

    Methods:
        __init__: Constructor for SiteManager class
        __len__: Returns the number of sites
        get_sites: Get all sites from the database
        add_site: Add a new site to the database
        delete_site: Delete a site from the database
        update_site: Update a site in the database
        _new_uuid: Generate a new UUID for a site
    '''

    def __init__(
        self,
        config: AppSettings,
    ) -> None:
        '''
        Constructor for SiteManager class
        Initializes the sites list

        Args:
            config (AppSettings): Application settings
        '''

        # Sql Server connection
        self.config = config
        self.sql_server = config.sql_server
        self.sql_database = config.sql_database
        self.table = 'sites'

        # List of all sites
        self.site_list = []

    def __len__(
        self
    ) -> int:
        '''
        Returns the number of sites

        Returns:
            int: Number of sites
        '''

        return len(self.site_list)

    def get_sites(
        self
    ) -> None:
        '''
        Get all sites from the database

        (1) Read all sites from SQL Server
        (2) Create class objects for each site
        (3) Append each object to a list

        Returns:
            list: A list of Site objects
        '''

        self.site_list = []

        # Read all sites from the database
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            output = sql.read(
                field='',
                value='',
            )

        if not output:
            print("Could not read from the database.")
            return

        # Reset site list and add all sites
        for site in output:
            self.site_list.append(
                Site(
                    name=site[1],
                    id=site[0]
                )
            )

    def add_site(
        self,
        name: str,
    ) -> Site:
        '''
        Add a new site to the database
        Assigns a new unique ID to the site
        Checks if the site name already exists

        Args:
            name (str): The name of the site

        Returns:
            Site: A new Site object if successful, otherwise None
        '''

        # Refresh the site list from the database
        self.get_sites()

        # Create a new unique ID for the site
        id = self._new_uuid()

        # Check if the name already exists in the database
        for site in self.site_list:
            # Names must be unique
            if name == site.name:
                print(
                    Fore.RED,
                    f"Site '{name}' already exists in the database.",
                    Style.RESET_ALL
                )
                return None

        # Create a new Site object
        print(
            Fore.GREEN,
            f"Adding site '{name}' with ID '{id}' to the database.",
            Style.RESET_ALL
        )
        new_site = Site(
            name=name,
            id=id
        )

        # Add to the database
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            result = sql.add(
                fields={
                    'id': new_site.id,
                    'name': new_site.name,
                }
            )

        if result:
            # Refresh the site list
            self.get_sites()
            return new_site

        else:
            print("Could not add site to the database.")
            return False

    def delete_site(
        self,
        id: uuid,
    ) -> bool:
        '''
        Delete a site from the database

        Args:
            id (uuid): The unique identifier for the site

        Returns:
            bool: True if successful, otherwise False
        '''

        # Refresh the site list from the database
        self.get_sites()

        # Delete the site from the database, based on the ID
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            result = sql.delete(
                field='id',
                value=id,
            )

        if result:
            # Refresh the site list
            self.get_sites()
            return True

        else:
            print("Could not delete site from the database.")
            return False

    def update_site(
        self,
        id: uuid,
        name: str,
    ) -> bool:
        '''
        Update a site in the database

        Args:
            id (uuid): The unique identifier for the site
            name (str): The new name for the site

        Returns:
            bool: True if successful, otherwise False
        '''

        # Some basic checks
        if id is None or id == '':
            print("Site ID is not provided.")
            return False

        if name is None or name == '':
            print("Site name is not provided.")
            return False

        # Update the site in the database, based on the ID
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            try:
                result = sql.update(
                    field='id',
                    value=id,
                    body={
                        'name': name,
                    }
                )

            except Exception as e:
                print(
                    Fore.RED,
                    "Could not update site in the database.",
                    Style.RESET_ALL,
                    e,
                )
                result = False

        if result:
            # Refresh the site list
            self.get_sites()
            return True

        else:
            print("Could not update site in the database.")
            return False

    def _new_uuid(
        self
    ) -> uuid:
        '''
        Generate a new UUID for a site
        Ensures the UUID is unique in the database

        Returns:
            UUID: A unique site UUID
        '''

        # Loop until a unique ID is found
        collision = True
        while collision:
            id = uuid.uuid4()
            collision = False

            for site in self.site_list:
                # If there is a collision, set the flag and break
                if id == site.id:
                    collision = True
                    break

        return id


class DeviceManager():
    '''
    A class to manage all devices
    Stores all devices in a list (from the database)
    Adds and removes devices

    Methods:
        __init__: Constructor for DeviceManager class
        __len__: Returns the number of devices
        __iter__: Iterate through the device list
        _create_device: Create a new Device object from a tuple
        _new_uuid: Generate a new UUID for a device
        _site_assignment: Assign devices to sites
        _ha_pairs: Find devices that are paired in an HA configuration
        get_devices: Get all devices from the database
        add_device: Add a new device to the database
        delete_device: Delete a device from the database
        update_device: Update a device in the database
        reset_password: Reset the password for a device
        id_to_name: Convert a device ID to a device name
    '''

    def __init__(
        self,
        config: AppSettings,
        site_manager: SiteManager,
    ) -> None:
        '''
        Constructor for DeviceManager class
        Initializes the devices list

        Args:
            config (AppSettings): Application settings
            site_manager (SiteManager): Site manager object
        '''

        # Sql Server connection
        self.sql_server = config.sql_server
        self.sql_database = config.sql_database
        self.table = 'devices'
        self.config = config

        # Site manager object
        self.site_manager = site_manager

        # List of all devices
        self.device_list = []
        self.ha_pairs = []

    def __len__(
        self
    ) -> int:
        '''
        Returns the number of devices in the list

        Returns:
            int: Number of devices
        '''

        return len(self.device_list)

    def __iter__(
        self,
    ) -> Device:
        '''
        Iterate through the device list
        '''

        self._index = 0
        return self

    def __next__(
        self,
    ) -> Device:
        '''
        Get the next device in the list
        '''

        if self._index < len(self.device_list):
            device = self.device_list[self._index]
            self._index += 1
            return device

        else:
            raise StopIteration

    def _create_device(
        self,
        device: tuple,
        config: AppSettings,
    ) -> Device:
        '''
        Create a new Device object from a tuple
        This is used in multithreading

        Args:
            device (tuple): A tuple of device details
            config (AppSettings): Application settings

        Returns:
            Device: A new Device object
        '''

        # Get the full vendor name (DB entry is in short form)
        vendor_list = {
            'paloalto': 'Palo Alto',
            'juniper': 'Juniper',
        }
        vendor = device[3]
        vendor_full_name = vendor_list.get(vendor, vendor)

        # Create the device object
        this_device = Device(
            id=device[0],
            hostname=device[1],
            site=device[2],
            key=device[9],
            username=device[6],
            password=device[7],
            salt=device[8],
            name=device[10] if device[10] is not None else "no-name",
            vendor=device[3],
            full_vendor=vendor_full_name,
            serial=device[11],
            ha_partner_serial=device[12],
            config=config,
        )

        # Collect the device details
        this_device.get_details()

        # Return the device object
        return this_device

    def _new_uuid(
        self
    ) -> uuid:
        '''
        Generate a new UUID for a device
        Ensures the UUID is unique in the database

        Returns:
            UUID: A unique device UUID
        '''

        # Loop until a unique ID is found
        collision = True
        while collision:
            id = uuid.uuid4()
            collision = False

            for device in self.device_list:
                # If there is a collision, set the flag and break
                if id == device.id:
                    collision = True
                    break

        return id

    def _site_assignment(
        self,
    ) -> None:
        '''
        Assign devices to sites

        Go through devices, and match to a site object
        Update the site object with the device ID
        '''

        # Reset the device list per site
        for site in self.site_manager.site_list:
            site.devices = []

        # Loop through devices and sites to find a match
        for device in self.device_list:
            # Reset the site name
            device.site_name = ''

            for site in self.site_manager.site_list:
                if device.site == site.id:
                    # Track the device in the site's list
                    site.devices.append(device.id)

                    # Track the site name in the device
                    device.site_name = site.name
                    break

    def _ha_pairs(
        self,
    ) -> None:
        '''
        Find devices that are paired in an HA configuration

        Loops devices to find active devices
        When one is found, loop through devices to find the passive device
        Store both in a dictionary, and append to a list
        '''

        # Loop through devices
        self.ha_pairs = []
        for device in self.device_list:
            # Find actice devices
            if device.ha_peer_serial and device.ha_local_state == 'active':
                # Loop through devices
                for peer in self.device_list:
                    # Find matching passive devices
                    if device.ha_peer_serial == peer.serial:
                        # Save the pair
                        self.ha_pairs.append({
                            'active': device,
                            'passive': peer
                        })
                        break

    def get_devices(
        self,
    ) -> None:
        '''
        Get all Palo Alto devices from the database

        (1) Read all devices from SQL Server
            Filter: Vendor must be 'paloalto'
        (2) Create class objects for each site
        (3) Append each object to a list
            This is done in a multithreaded manner
        '''

        # Read paloalto devices from the database
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            output = sql.read(
                field='type',
                value='firewall',
            )

        if not output:
            print("Could not read from the database.")
            return

        # Create a list of Device objects
        #   Iterate through the device list in SQL output
        self.device_list = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(
                    self._create_device, device, self.config
                ) for device in output
            ]
            for future in concurrent.futures.as_completed(futures):
                self.device_list.append(future.result())

        # Assign devices to sites
        self._site_assignment()

        # Find HA pairs
        self._ha_pairs()

    def add_device(
        self,
        name: str,
        hostname: str,
        site: uuid,
        vendor: str,
        key: str,
        username: str,
        password: str,
        salt: str,
    ) -> Device:
        '''
        Add a new device to the database
        Assigns a new unique ID to the device
        Checks if the device name already exists

        Args:
            friendly_name (str): The name of the device
            hostname (str): The hostname of the device
            site (uuid): The site identifier for the device
            vendor (str): The vendor of the device
            key (str): The REST API key for the device
            username (str): The username for the device (XML API)
            password (str): The encrypted password for the device (XML API)
            salt (str): The salt for the password (XML API)

        Returns:
            Device: A new Device object if successful, otherwise None
        '''

        # Confirm the API key is valid
        if key == '' or len(key) < 32:
            print(
                Fore.RED,
                f"API key '{key}' is invalid.",
                Style.RESET_ALL
            )
            return None

        # Check if the site exists
        site_ids = []
        for site_id in self.site_manager.site_list:
            site_ids.append(str(site_id.id))

        if site not in site_ids:
            print(
                Fore.RED,
                f"Site '{site}' does not exist in the database.",
                Style.RESET_ALL
            )
            return None

        # Create a new unique ID for the device
        id = self._new_uuid()

        # Check if the name already exists in the database
        for device in self.device_list:
            # Names must be unique
            if hostname == device.hostname:
                print(
                    Fore.RED,
                    f"Device '{hostname}' already exists in the database.",
                    Style.RESET_ALL
                )
                return None

        with CryptoSecret() as encryptor:
            # Encrypt the password
            encrypted = encryptor.encrypt(password)
            password_encoded = encrypted[0].decode()
            salt_encoded = base64.b64encode(encrypted[1]).decode()

        # Create a new Device object
        print(
            Fore.GREEN,
            f"Adding device '{hostname}' with ID '{id}' to the database.",
            Style.RESET_ALL
        )
        new_device = Device(
            name=name,
            id=id,
            hostname=hostname,
            site=site,
            vendor=vendor,
            key=key,
            username=username,
            password=password_encoded,
            salt=salt_encoded,
            config=self.config,
        )

        # Add to the database
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            result = sql.add(
                fields={
                    'id': new_device.id,
                    'name': new_device.hostname,
                    'friendly_name': new_device.name,
                    'site': new_device.site,
                    'vendor': vendor,
                    'type': 'firewall',
                    'auth_type': 'token',
                    'username': username,
                    'secret': password,
                    'salt': salt,
                    'token': new_device.key,
                }
            )

        if result:
            return new_device

        else:
            print("Could not add device to the database.")
            return False

    def delete_device(
        self,
        id: uuid,
    ) -> bool:
        '''
        Delete a device from the database

        Args:
            id (uuid): The unique identifier for the device

        Returns:
            bool: True if successful, otherwise False
        '''

        # Delete the device from the database, based on the ID
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            result = sql.delete(
                field='id',
                value=id,
            )

        if result:
            # Refresh the site list
            # self.get_devices()
            return True

        else:
            print("Could not delete device from the database.")
            return False

    def update_device(
        self,
        id: uuid,
        name: str,
        hostname: str,
        site: uuid,
        vendor: str,
        key: str,
        username: str,
        password: str,
        salt: str,
    ) -> bool:
        '''
        Update a device in the database

        Args:
            id (uuid): The unique identifier for the device
            name (str): The new name for the device
            hostname (str): The new hostname for the device
            site (uuid): The new site for the device
            vendor (str): The new vendor for the device
            key (str): The new REST API key for the device
            username (str): The new username for the device (XML API)
            password (str): The new encrypted password for the device (XML API)
            salt (str): The new salt for the password (XML API)

        Returns:
            bool: True if successful, otherwise False
        '''

        # Refresh the device list from the database
        print(
            Fore.CYAN,
            "Refreshing device list before update.",
            Style.RESET_ALL
        )
        self.get_devices()

        # Update the device in the database, based on the ID
        with SqlServer(
            server=self.sql_server,
            database=self.sql_database,
            table=self.table,
            config=self.config,
        ) as sql:
            try:
                result = sql.update(
                    field='id',
                    value=id,
                    body={
                        'friendly_name': name,
                        'name': hostname,
                        'site': site,
                        'vendor': vendor,
                        'token': key,
                        'username': username,
                        'secret': password,
                        'salt': salt,
                    }
                )

            except Exception as e:
                print(
                    Fore.RED,
                    "Could not update device in the database.",
                    Style.RESET_ALL,
                    e,
                )
                result = False

        if result:
            # Refresh the device list
            self.get_devices()
            return True

        else:
            print("Could not update device in the database.")
            return False

    def id_to_name(
        self,
        id: uuid,
    ) -> str:
        '''
        Convert a device ID to a device name

        Args:
            id (uuid): The unique identifier for the device

        Returns:
            str: The device name
        '''

        # Check if the ID matches a device
        for device in self.device_list:
            if str(id) == str(device.id):
                return device.hostname

        # If no match is found, return None
        return None


# Manage the sites and devices
if config.config_exists and config.config_valid:
    site_manager = SiteManager(config)
    device_manager = DeviceManager(config, site_manager)

elif config.config_exists is False:
    print(
        Fore.YELLOW,
        "There is no config file. Please create one.",
        Style.RESET_ALL
    )
    site_manager = None
    device_manager = None

else:
    print(
        Fore.YELLOW,
        "The config file is invalid. Please correct it.",
        Style.RESET_ALL
    )
    site_manager = None
    device_manager = None
