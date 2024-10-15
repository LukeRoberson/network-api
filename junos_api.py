'''
Classes to access Junos firewalls through the API

Junos supports two APIs:
    REST API
    NETCONF

This module uses the NETCONF API, with the pyEZ library
    By default, this returns a list of 'facts' about the device

PyEZ usage details:
    https://www.juniper.net/documentation/en_US/day-one-books/DO_PyEZ_Cookbook.pdf

Authentication:
    The Junos device must be configured to allow NETCONF access
        'set system services netconf ssh'

    The pyEZ library uses SSH to connect to the device,
        passing a username and password
    This user must have suitable permissions to access the device
'''


from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import (
    ConnectError,
    ConnectAuthError,
    ConnectTimeoutError,
)

from lxml import etree
import json
import xmltodict
import ipaddress

from typing import Union, Tuple
from colorama import Fore, Style


class DeviceApi:
    '''
    Class to access Junos devices through the NETCONF API

    Methods:
        __init__: Initialise the class with the device details
        __enter__: Context manager
        __exit__: Context manager
        get_device: Get device basics from the device
        get_ha: Get high availability details
        get_config: Get the running configuration of the device
        get_partial_config: Gets a partial configuration based on a path
        _add_config: Add configuration to the device
        get_addresses: Gets address books, objects, and sets
        create_address: Create an address object
        get_address_groups: An alias for get_addresses
        create_addr_group: Create an address group
        get_application_groups: Gets application groups
        create_app_group: Create an application group
        get_services: Gets services
        create_service: Create a service object
        get_service_groups: Gets service groups
        create_service_group: Create a service group
        get_nat_policies: Gets NAT policies
        get_security_policies: Gets security policies
        get_qos_policies: Gets QoS policies
        get_vpn_status: Gets the current IKE SA status
    '''

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
    ) -> None:
        '''
        Initialise the class with the device details

        Args:
            hostname (str): The hostname or IP address of the device
            username (str): The username to connect with
            password (str): The password to connect with
        '''

        # Device details
        self.hostname = hostname
        self.username = username
        self.password = password

        # Connect to the device
        self.device = Device(
            host=self.hostname,
            user=self.username,
            passwd=self.password
        )
        try:
            self.device.open()

        except ConnectAuthError:
            print(
                Fore.RED,
                f"Failed to authenticate to {self.hostname}",
                Style.RESET_ALL
            )

        except ConnectTimeoutError:
            print(
                Fore.RED,
                f"Timeout connecting to {self.hostname}",
                Style.RESET_ALL
            )

        except ConnectError as e:
            if 'ConnectClosedError' in str(e):
                print(
                    Fore.RED,
                    f"Connection to {self.hostname} closed",
                    "Possibly too many connections",
                    Style.RESET_ALL,
                    e,
                )
            else:
                print(
                    Fore.RED,
                    f"Error connecting to {self.hostname}",
                    Style.RESET_ALL
                )

        except Exception as e:
            print(
                Fore.RED,
                f"Generic error connecting to {self.hostname}",
                Style.RESET_ALL
            )
            print(
                Fore.YELLOW,
                e,
                Style.RESET_ALL
            )

    def __enter__(
        self
    ) -> 'DeviceApi':
        '''
        Context manager

        Returns:
            DeviceApi: The current instance
        '''

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback
    ) -> None:
        '''
        Context manager

        Args:
            exc_type: Exception type
            exc_value: Exception value
            traceback: Traceback
        '''

        # handle errors that were raised
        if exc_type:
            print(
                f"Exception of type {exc_type.__name__} occurred: {exc_value}",
                exc_info=(exc_type, exc_value, traceback)
            )

    def get_device(
        self
    ) -> Union[Tuple[str, str, str], int]:
        '''
        Get device basics from the device

        Returns:
            Tuple[str, str, str]: The device details
                The model, serial number, and software version of the device.
            int: The response code if an error occurred.
        '''

        # Get basics from the device 'facts'
        model = self.device.facts['model']
        serial = self.device.facts['serialnumber']
        version = self.device.facts['version']

        return model, serial, version

    def get_ha(
        self
    ) -> Union[bool, Tuple[bool, str, str, str], int]:
        '''
        Get high availability details.

        Returns:
            bool:
                Whether the device is enabled (False if HA is disabled).
            Tuple[bool, str, str, str]:
                Whether the device is enabled, local state,
                    peer state, and peer serial number.
            int:
                The response code if an error occurred.
        '''

        enabled = False
        local_state = None
        peer_state = None
        peer_serial = None

        return enabled, local_state, peer_state, peer_serial

    def get_config(
        self
    ) -> Union[str, int]:
        '''
        Get the running configuration of the device

        Returns:
            str: The configuration
            int: The response code if an error occurred.
        '''

        # Get the committed config
        dev_config = self.device.rpc.get_config(
            options={
                'database': 'committed',
                'format': 'set'
            }
        )

        # Cleanup the config
        cleaned = etree.tostring(dev_config, encoding='unicode')
        cleaned = cleaned.replace('<configuration-set>', '')
        cleaned = cleaned.replace('</configuration-set>', '')
        cleaned = "\n".join(
            [line for line in cleaned.splitlines() if line.strip()]
        )

        return cleaned

    def get_partial_config(
        self,
        path,
        inherit=True,
    ):
        '''
        Gets a partial configuration based on a path
        A path must be provided (can't be empty or start with a slash)
        If inherit is True, inherited configuration is included

        Args:
            path (str): Path to the configuration to get
            inherit (bool): Include inherited configuration (default: True)

        Returns:
            dict: Configuration details
        '''

        # Input validation
        if path is None or path == '':
            print(
                Fore.RED,
                'Error: Path not provided',
                Style.RESET_ALL
            )
            return None

        if path[0] == '/':
            print(
                Fore.RED,
                'Error: Path should not start with /',
                Style.RESET_ALL
            )
            return None

        # Set inherit value
        if inherit is True:
            inherit = 'inherit'
        else:
            inherit = ''

        # Get the config
        try:
            result = self.device.rpc.get_config(
                filter_xml=path,
                options={
                    'format': 'json',
                    'inherit': inherit,
                }
            )

        except Exception as e:
            if 'NoneType' not in str(e):
                print(Fore.RED, f'Error: {e}', Style.RESET_ALL)

            return None

        # Filter the results nicely
        path_list = path.split('/')
        result = result['configuration']

        if path_list[0] not in result:
            return None

        for item in path_list:
            result = result[item]

        return result

    def _add_config(
        self,
        config: dict,
    ) -> str:
        '''
        Add configuration to the device
        NOTE: This does not commit the changes

        Args:
            config (dict): Configuration to add
                This is converted to a JSON string

        Returns:
            str: Diff of the changes on the device
        '''

        # Convert dictionary to JSON string
        config = json.dumps(config)

        # Load the configuration
        with Config(self.device) as cu:
            # Load the configuration
            try:
                cu.load(
                    config,
                    format='json',
                    merge=True,
                )
            except Exception as e:
                print(Fore.RED, f'Error: {e}', Style.RESET_ALL)
                return None

            # Compare the changes
            changes = cu.diff()

        return changes

    def get_addresses(
        self
    ) -> list:
        '''
        Gets:
            - Address books
            - Address objects
            - Address sets (groups of addresses)

        Add addresses and address sets are part of an address book

        Returns:
            list: The addresses
                name (str): The name of the address book
                address (list): The addresses in the address book
                    name (str): The name of the address
                    ip-prefix (str): The IP prefix of the address
                address-set (list): The address sets in the address book
                    name (str): The name of the address set
                    address (list): The addresses in the address set
                        name (str): The name of the address object
        '''

        addresses = self.get_partial_config(
            path='security/address-book',
            inherit=True,
        )

        return addresses

    def create_address(
        self,
        name: str,
        address: str,
        description: str = '',
        address_book: str = 'global',
    ) -> str:
        '''
        Config template for adding an address object

        Args:
            name (str): Name of the address object
            address (str): IP prefix of the address object
                This can be a single IP or a range
                eg:
                    1.1.1.1, 1.1.1.1/32, 1.1.1.0/24
                    1.1.1.1-1.1.1.4
            description (str): Description of the address object
            address_book (str): Name of the address book (default: 'global')

        Returns:
            str: Diff of the changes on the device
        '''

        # Check if we have a range or a single IP
        if '-' in address:
            address = address.split('-')

            # Check if we have a valid range
            if len(address) != 2:
                print(
                    Fore.RED,
                    'Error: Invalid prefix range',
                    Style.RESET_ALL
                )
                return None

        else:
            address = [address]

        # Sanity check for 'prefix'
        for addr in address:
            try:
                ipaddress.ip_network(addr)
            except ValueError as e:
                print(Fore.RED, f'Error: {e}', Style.RESET_ALL)
                return None

        # Single IP address
        if len(address) == 1:
            config_template = {
                "configuration": {
                    "security": {
                        "address-book": [
                            {
                                "name": address_book,
                                "address": [
                                    {
                                        "name": name,
                                        "description": description,
                                        "ip-prefix": address[0]
                                    }
                                ]
                            }
                        ]
                    }
                }
            }

        # Range of IP addresses
        elif len(address) == 2:
            config_template = {
                "configuration": {
                    "security": {
                        "address-book": [
                            {
                                "name": address_book,
                                "address": [
                                    {
                                        "name": name,
                                        "range-address": [
                                            {
                                                "name": address[0],
                                                "to": {
                                                    "range-high": address[1]
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            }

        return self._add_config(config_template)

    def get_address_groups(
        self
    ) -> list:
        '''
        An Alias for get_addresses
        This is to match other APIs that don't include addresses
            and address sets together
        '''

        addresses = self.get_partial_config(
            path='security/address-book',
            inherit=True,
        )

        return addresses

    def create_addr_group(
        self,
        name: str,
        members: list,
        address_book: str = 'global',
    ) -> str:
        '''
        Config template for adding an address group
            This is an 'address-set' in junos

        Args:
            name (str): Name of the address group
            members (list): List of address objects to include
            address_book (str): Name of the address book (default: 'global')

        Returns:
            str: Diff of the changes on the device
        '''

        # Sanity check for 'members'
        if not members:
            print(
                Fore.RED,
                'Error: No members provided',
                Style.RESET_ALL
            )
            return None

        if type(members) is not list:
            print(
                Fore.RED,
                'Error: Members should be a list',
                Style.RESET_ALL
            )
            return None

        # Create the configuration template
        config_template = {
            "configuration": {
                "security": {
                    "address-book": [
                        {
                            "name": address_book,
                            "address-set": [
                                {
                                    "name": name,
                                    "address": [
                                        {"name": member} for member in members
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        }

        return self._add_config(config_template)

    def get_application_groups(
        self
    ):
        '''
        Gets application groups
            This is part of the app-id license

        Returns:
            list: Dictionaries of application groups
                name (str): The name of the application
                applications (list): The applications in the group
                    name (str): The name of the application
        '''

        app_groups = self.get_partial_config(
            path='services/application-identification/application-group',
            inherit=True,
        )

        return app_groups

    def create_app_group(
        self,
        name: str,
        members: list,
    ) -> str:
        '''
        Config template for adding a application group

        Args:
            name (str): Name of the application group
            members (list): List of applications to include

        Returns:
            str: Diff of the changes on the device
        '''

        # Sanity check for 'members'
        if not members:
            print(
                Fore.RED,
                'Error: No members provided',
                Style.RESET_ALL
            )
            return None

        if type(members) is not list:
            print(
                Fore.RED,
                'Error: Members should be a list',
                Style.RESET_ALL
            )
            return None

        # Create the configuration template
        config_template = {
            "configuration": {
                "services": {
                    "application-identification": {
                        "application-group": [
                            {
                                "name": name,
                                "applications": [
                                    {"name": member} for member in members
                                ]
                            }
                        ]
                    }
                }
            }
        }

        return self._add_config(config_template)

    def get_services(
        self
    ):
        '''
        Gets services

        Returns:
            list: Dictionaries of services
                name (str): The name of the service
                description (str): The description of the service
                protocol (str): The protocol of the service
                destination-port (str): The destination port of the service
                source-port (str): The source port of the service
        '''

        services = self.get_partial_config(
            path='applications/application',
            inherit=True,
        )

        return services

    def create_service(
        self,
        name: str,
        protocol: str,
        dest_port: str,
        description: str = '',
    ) -> str:
        '''
        Config template for adding a service object
            This is an 'application' in junos

        Args:
            name (str): Name of the service object
            description (str): Description of the service object
            protocol (str): Protocol of the service object
                eg: tcp, udp, icmp
            dest_port (str): Destination port of the service object

        Returns:
            str: Diff of the changes on the device
        '''

        # Create the configuration template
        config_template = {
            "configuration": {
                "applications": {
                    "application": [
                        {
                            "name": name,
                            "description": description,
                            "protocol": protocol,
                            "destination-port": dest_port
                        }
                    ]
                }
            }
        }

        return self._add_config(config_template)

    def get_service_groups(
        self
    ):
        '''
        Gets service groups
            This is an 'application-set' in Junos

        Returns:
            list: Dictionaries of service groups
                name (str): The name of the service group
                description (str): The description of the service group
                application (list): The applications in the group
                    name (str): The name of the application object
        '''

        service_groups = self.get_partial_config(
            path='applications/application-set',
            inherit=True,
        )

        return service_groups

    def create_service_group(
        self,
        name: str,
        description: str,
        members: list,
    ) -> str:
        '''
        Config template for adding a service group
            This is an 'application-set' in junos

        Args:
            name (str): Name of the service group
            description (str): Description of the service group
            members (list): List of service objects to include

        Returns:
            str: Diff of the changes on the device
        '''

        # Sanity check for 'members'
        if not members:
            print(
                Fore.RED,
                'Error: No members provided',
                Style.RESET_ALL
            )
            return None

        if type(members) is not list:
            print(
                Fore.RED,
                'Error: Members should be a list',
                Style.RESET_ALL
            )
            return None

        # Create the configuration template
        config_template = {
            "configuration": {
                "applications": {
                    "application-set": [
                        {
                            "name": name,
                            "description": description,
                            "application": [
                                {"name": member} for member in members
                            ]
                        }
                    ]
                }
            }
        }
        print(config_template)

        return self._add_config(config_template)

    def get_nat_policies(
        self
    ):
        '''
        Gets NAT policies
            This can be source or destination NAT

        Notes:
            interfaces may be 'null' if the NAT is not interface-based

        Returns:
            dict: Dictionaries source and destination NAT policies
                source (dict): Source NAT policies
                    rule-set (list of dicts): The source NAT rule sets
                        name (str): The name of the rule set
                        from (dict): The source zone
                            zone (list of str): The source zones
                        to (dict): The destination zone
                            zone (list of str): The destination zones
                        rule (list of dicts): The source NAT rules
                            name (str): The name of the rule
                            src-nat-rule-match (dict): The source NAT match
                                source-address (list of str): Source networks
                            then (dict): The source NAT action
                                source-nat (dict): The source NAT details
                                    interface (list of str): The source int

                destination (dict): Destination NAT policies
                    pool (list of dicts): The destination NAT pools
                        name (str): The name of the pool
                        routng-instance (dict): The routing instance
                            ri-name (str): The name of the routing instance
                        address (dict): The address of the pool
                            ip-prefix (str): The IP prefix of the pool
                    rule-set (list of dicts): The destination NAT rule sets
                        name (str): The rule set name
                        from (dict): The source zone
                            zone (list of str): The source zones
                        rule (list of dicts): The destination NAT rules
                            name (str): The name of the rule
                            dest-nat-rule-match (dict): The d-NAT match
                                destination-address (dict): The dest address
                                    dst-addr: (str): The destination address
                                destination-port (list of dict): The dest port
                                    name (int): The destination port
                            then (dict): The destination NAT action
                                destination-nat (dict): The d-NAT details
                                    pool (list of str): The destination NAT
                                        pool-name (str): The pool name
        '''

        nat_policy = self.get_partial_config(
            path='applications/application-set',
            inherit=True,
        )

        return nat_policy

    def get_security_policies(
        self
    ):
        '''
        Gets security policies

        Returns:
            list of dicts: Dictionaries of security policies
                from-zone-name (str): The source zone
                to-zone-name (str): The destination zone
                policy (list of dicts): The security policies
                    name (str): The name of the policy
                    match (dict): The match criteria
                        source-address (list of str): The source addresses
                        destination-address (list of str): The dest addresses
                        application (list of str): The applications
                    then (dict): The action
                        permit (dict): The permit action
                        log (dict): The log action
                        count (dict): The count action
                        deny (dict): The deny action
        '''

        service_groups = self.get_partial_config(
            path='security/policies/policy',
            inherit=True,
        )

        return service_groups

    def get_qos_policies(
        self
    ):
        '''
        Gets QoS policies

        Returns:
            dict: Dictionaries of QoS policies
                classifiers (dict): The classifiers
                    dscp (list of dicts): The DSCP classifiers
                        name (str): The name of the classifier
                        forwarding-class (list): The forwarding classes
                            name (str): The name of the forwarding class
                            loss-priority (list): The loss priorities
                                name (str): The name of the loss priority
                                code-point (list of str): The code point
                drop-profiles (list of dicts): The drop profiles
                    name (str): The name of the drop profile
                    drop-profile-map (list): The drop profile map
                        name (str): The name of the drop profile map
                        drop-profile (list): The drop profiles
                            name (str): The name of the drop profile
                            interpolate (dict): The interpolate values
                                fill-level (list of ints): The fill levels
                                drop-probability (list of ints): The drop probs
                forwarding-classes (dict): The forwarding classes
                    queue (list of dicts): The queues
                        name (str): Queue name
                        class-name (str): The class name
                interfaces (dict): The interfaces
                    interface (list of dicts): The interfaces
                        name (str): The interface name
                        shaping-rate (dict): The shaping rate
                            rate (str): The shaping rate
                        unit (list of dicts): The interface units
                            name (int): The unit number
                            scheduler-map (str): The assigned scheduler map
                            classifiers (dict): The assigned classifiers
                                dscp (list of dicts): Assigned DSCP classifiers
                                    name (str): The name of the classifier
                rewrite-rules (dict): The rewrite rules
                    dscp: (list of dicts): The DSCP rewrite rules
                        name (str): The name of the rewrite rule
                        forwarding-class (list of dicts): Forwarding classes
                            name (str): The name of the forwarding class
                            loss-priority (list of dicts): The loss priorities
                                name (str): The name of the loss priority
                                code-point (str): The code point
                scheduler-maps (list of dicts): The scheduler maps
                    name (str): The name of the scheduler map
                    forwarding-class (list of dicts): The forwarding classes
                        name (str): The name of the forwarding class
                        scheduler (str): The assigned scheduler
                schedulers (list of dicts): The schedulers
                    name (str): The name of the scheduler
                    transmit-rate (dict): The transmit rate
                        percent (int): The transmit rate percentage
                    buffer-size (dict): The buffer size
                        percent (int): The buffer size percentage
                    drop-profile-map (list of dicts): The drop profile map
                        loss-priority (str): The loss priority
                        protocol (str): The protocol
                        drop-profile (str): The drop profile
                    priority (str): The priority name
        '''

        service_groups = self.get_partial_config(
            path='class-of-service',
            inherit=True,
        )

        return service_groups

    def get_vpn_status(
        self,
    ) -> dict:
        '''
        Gets the current IKE SA status
            Sends an RPC to get the IKE SA information

        This is initially an XML element, so it is converted

        Returns:
            dict: IKE SA status
        '''

        # Get the IKE gateway configuration
        ike_gw = self.get_partial_config('security/ike/gateway', inherit=True)

        # Get the current IKE status
        ike_sa = self.device.rpc.get_ike_security_associations_information()
        ike_sa = xmltodict.parse(
            etree.tostring(
                ike_sa,
                encoding='unicode'
            )
        )
        ike_sa = ike_sa["ike-security-associations-information"]
        ike_sa = ike_sa["ike-security-associations"]

        # Get the IPsec gateway configuration
        ipsec_gw = self.get_partial_config('security/ipsec/vpn', inherit=True)

        # Get the current IPsec status
        ipsec_sa = self.device.rpc.get_security_associations_information()
        ipsec_sa = xmltodict.parse(
            etree.tostring(
                ipsec_sa,
                encoding='unicode'
            )
        )
        ipsec_sa = ipsec_sa["ipsec-security-associations-information"]
        ipsec_sa = ipsec_sa["ipsec-security-associations-block"]

        # Select the relevant information
        vpn_status = []
        for gateway in ike_gw:
            vpn = {}

            # Parse through the IKE GW configuration
            vpn['ike_name'] = gateway["name"]
            if 'address' in gateway:
                vpn['ike_address'] = gateway["address"][0]
            else:
                vpn['ike_address'] = 'dynamic'
            vpn['ike_interface'] = gateway["external-interface"]

            # Find matching SA, if any
            for sa in ike_sa:
                if sa["ike-sa-remote-address"] == vpn['ike_address']:
                    vpn['ike_state'] = sa['ike-sa-state']
                    vpn['ike_version'] = sa['ike-sa-exchange-type']
                    break
            if 'ike_state' not in vpn:
                vpn['ike_state'] = 'DOWN'
                vpn['ike_version'] = 'N/A'

            # Find matching IPsec VPN, if any
            for gateway in ipsec_gw:
                if gateway["ike"]["gateway"] == vpn['ike_name']:
                    vpn['ipsec_name'] = gateway["name"]
                    vpn['ipsec_interface'] = gateway["bind-interface"]
                    break
            if 'ipsec_name' not in vpn:
                vpn['ipsec_name'] = 'N/A'
                vpn['ipsec_interface'] = 'N/A'

            # Find matching IPsec SA, if any
            for sa in ipsec_sa:
                details = sa["ipsec-security-associations"][0]
                if details["sa-remote-gateway"] == vpn['ike_address']:
                    vpn['ipsec_state'] = sa["sa-block-state"]
                    vpn['ipsec_port'] = details["sa-port"]
                    vpn['ipsec_protocol'] = details["sa-protocol"]
                    vpn['ipsec_alg'] = details["sa-esp-encryption-algorithm"]
                    vpn['ipsec_hmac'] = details["sa-hmac-algorithm"]
                    break
            if 'ipsec_state' not in vpn:
                vpn['ipsec_state'] = 'DOWN'
                vpn['ipsec_port'] = 'N/A'
                vpn['ipsec_protocol'] = 'N/A'
                vpn['ipsec_alg'] = 'N/A'
                vpn['ipsec_hmac'] = 'N/A'

            vpn_status.append(vpn)

        return vpn_status
