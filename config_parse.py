'''
Class to load app configuration
    Reads from a YAML file and stores the settings
'''

from yaml import safe_load, safe_dump
from colorama import Fore, Style


class AppSettings():
    '''
    Track all application settings
    Stored in YAML file, so this must be read and updated

    Methods:
        _read_config: Read the configuration file
        _validate_config: Validate the configuration file
        write_config: Write the configuration file
    '''

    def __init__(
        self
    ) -> None:
        '''
        Initialize the settings

        Validation flags:
            config_exists: True if the config file exists
            config_valid: True if the config file is valid
                This doesn't mean the settings are correct,
                    just that the file is valid
        '''

        # Validation flags
        self.config_exists = False
        self.config_valid = False

        # Get settings from the yaml file
        self._read_config()

    def _read_config(
        self
    ) -> None:
        '''
        Read the configuration file (config.yaml)
        Validate that it exists and is valid
        '''

        # Read the configuration file
        try:
            with open('config.yaml') as f:
                config = safe_load(f)

        except FileNotFoundError:
            self.config_exists = False
            print(
                Fore.RED,
                'Config file not found',
                Style.RESET_ALL
            )
            return
        self.config_exists = True

        # Validate the configuration file
        self._validate_config(config)
        if self.config_valid is not True:
            print(
                Fore.RED,
                'Config file is invalid',
                Style.RESET_ALL
            )
            return

        # SQL settings
        self.sql_server = config['sql']['server']
        self.sql_port = config['sql']['port']
        self.sql_database = config['sql']['database']
        self.sql_auth_type = config['sql']['auth-type']
        self.sql_username = config['sql']['username']
        self.sql_password = config['sql']['password']
        self.sql_salt = config['sql']['salt']

        # Web server settings
        self.web_ip = config['web']['ip']
        self.web_port = config['web']['port']
        self.web_debug = config['web']['debug']

    def _validate_config(
        self,
        config: dict,
    ) -> None:
        '''
        Validate the configuration file settings
            This is to ensure all settings are present
            Does not check if the settings are correct

        1. Check for the 'sql' section
        2. Check for the 'web' section
        3. Check that 'debug' is true/false

        Args:
            config (dict): The configuration settings
        '''

        # Check for the 'sql' section
        if 'sql' not in config:
            print(
                Fore.RED,
                "Config: The 'sql' section is missing from the config file.",
                Style.RESET_ALL
            )
            self.config_valid = False
            return

        # Check that sql config parameters all exist in the sql section
        params = [
            'server', 'port', 'database',
            'auth-type', 'username', 'password', 'salt'
        ]
        if not all(key in config['sql'] for key in params):
            print(
                Fore.RED,
                "Config: All parameters need to exist in the SQL section:\n",
                "'server', 'port', 'database',",
                " 'auth-type', 'username', 'password', 'salt'",
                Style.RESET_ALL
            )
            self.config_valid = False
            return

        # Check for the 'web' section
        if 'web' not in config:
            print(
                Fore.RED,
                "Config: The 'web' section is missing from the config file.",
                Style.RESET_ALL
            )
            self.config_valid = False
            return

        # Check that 'debug', 'ip', 'port'
        #   all exist in the web section
        if not all(
            key in config['web'] for key in ['debug', 'ip', 'port']
        ):
            print(
                Fore.RED,
                "Config: All parameters need to exist in the web section:\n",
                "'debug', 'ip', 'port'",
                Style.RESET_ALL
            )
            self.config_valid = False
            return

        # Check that 'debug' is set to true/false
        debug = config.get('web', {}).get('debug')
        if debug is not True and debug is not False:
            print(
                Fore.RED,
                "Config: The 'debug' setting must be true or false.",
                Style.RESET_ALL
            )
            self.config_valid = False
            return

        # When all checks pass
        self.config_valid = True

    def write_config(self) -> None:
        '''
        Write the configuration file (config.yaml)
        This is to update settings
        '''

        # Write the configuration file
        config = {
            'sql': {
                'server': self.sql_server,
                'port': self.sql_port,
                'database': self.sql_database,
                'auth-type': self.sql_auth_type,
                'username': self.sql_username,
                'password': self.sql_password,
                'salt': self.sql_salt,
            },
            'web': {
                'ip': self.web_ip,
                'port': self.web_port,
                'debug': self.web_debug,
            }
        }

        try:
            with open('config.yaml', 'w') as f:
                safe_dump(config, f)

        except Exception as e:
            print(e)


# Instantiate the object
config = AppSettings()
