"""
Creates and reads entries in an SQL database
"""

import pymssql
import traceback as tb
from colorama import Fore, Style
import base64

from config_parse import AppSettings
from encryption import CryptoSecret


class SqlServer:
    '''
    Connect to an SQL server/database to read and write
    Supports being instantiated with the 'with' statement

    Methods:
        __init__()
            Class constructor
        __enter__()
            Called when the 'with' statement is used
        __exit__()
            Called when the 'with' statement is finished
        connect()
            Connect to an SQL server
        disconnect()
            Gracefully disconnect from the server
        create_table()
            Create a table
        add()
            Add a record
        read()
            Read a record
        update()
            Update a record
        delete()
            Delete a record
    '''

    def __init__(
        self,
        server: str,
        database: str,
        table: str,
        port: int = 1433,
        config: AppSettings = None
    ) -> None:
        '''
        Class constructor

        Gets the SQL server/db/table names
        Sets up empty connection and cursor objects

        Authentication can be Windows integrated or SQL Server
            This is based on the settings in the config object

        Args:
            server : str
                The server name
            database : str
                The database name
            table : str
                The table name
            port : int
                The port number (default is 1433)
            config : AppSettings
                The settings object
        '''

        # Settings
        self.config = config

        # SQL server information
        self.server = server
        self.port = port
        self.db = database
        self.table = table

        # Connection and cursor objects
        self.conn = None
        self.cursor = None

    def __enter__(
        self
    ) -> 'SqlServer':
        """
        Called when the 'with' statement is used
        Calls the 'connect' method to connect to the server

        Returns:
            self
                The instantiated object
        """

        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Exception | None,
        exc_value: Exception | None,
        traceback: Exception | None,
    ) -> None:
        """
        Called when the 'with' statement is finished
        Calls the 'disconnect' method to gracefully close the connection
            to the server

        Args:
            exc_type : Exception
                The type of exception raised
            exc_value : Exception
                The value of the exception raised
            traceback : Exception
                The traceback of the exception raised
        """

        # Close the connection to the server
        self.disconnect()

        # handle errors that were raised
        if exc_type:
            print(
                f"Exception of type {exc_type.__name__} occurred: {exc_value}"
            )
            if traceback:
                print("Traceback:")
                print(tb.format_tb(traceback))

    def test_connection(
        self
    ) -> bool:
        '''
        A simple method to test the connection to the SQL server

        Returns:
            True : bool
                If the connection was successful
            False : bool
                If the connection failed
        '''

        # Attempt to connect to the database
        result = self.connect()
        print(f"Connection result: {result}")

        if result:
            self.disconnect()
            return True
        else:
            return False

    def connect(
        self
    ) -> bool:
        '''
        Connect to the SQL server
        Use SQL or integrated Windows authentication based on the settings

        Returns:
            True : bool
                If the connection was successful
        '''

        # Connect to the server and database
        try:
            if self.config.sql_auth_type == 'SQL':
                # Decrypt the password in the settings
                with CryptoSecret() as decryptor:
                    real_pw = decryptor.decrypt(
                        secret=self.config.sql_password,
                        salt=base64.urlsafe_b64decode(
                            self.config.sql_salt.encode()
                        )
                    )

                # Connect to the server
                self.conn = pymssql.connect(
                    server=f"{self.server}:{self.port}",
                    database=self.db,
                    user=self.config.sql_username,
                    password=real_pw,
                )

            else:
                # Connect using Windows authentication
                self.conn = pymssql.connect(
                    server=f"{self.server}:{self.port}",
                    database=self.db,
                )

        # Handle errors
        except pymssql.OperationalError as e:
            error_code, error_message = e.args[0]
            if error_code == 20009:
                print(
                    Fore.RED,
                    "Unable to connect to the database server.\n",
                    Fore.YELLOW,
                    "The server may be unavailable or the server"
                    " address might be incorrect.",
                    Style.RESET_ALL,
                )
            elif error_code == 18456:
                print(
                    Fore.RED,
                    "Unable to connect to the database server.\n",
                    Fore.YELLOW,
                    "The username or password may be incorrect.",
                    Style.RESET_ALL,
                )
            else:
                print(f"Operational error: {error_code}: {error_message}\n")
            return False

        except pymssql.DataError as e:
            print(f"Data error: {e}\n")
            return False

        except pymssql.IntegrityError as e:
            print(f"Integrity error: {e}\n")
            return False

        except pymssql.InternalError as e:
            print(f"Internal error: {e}\n")
            return False

        except Exception as e:
            print(f"Connection error: {e}\n")
            return False

        self.cursor = self.conn.cursor()
        return True

    def disconnect(
        self
    ) -> None:
        """
        Gracefully close the connection to the server
        """

        if self.cursor:
            self.cursor.close()

        if self.conn:
            self.conn.close()

    def create_table(
        self,
        fields: dict[str, str]
    ) -> bool:
        '''
        Creates a table in an SQL database

        Args:
            fields : dict
                Fields to create in the table

        Returns:
            True : bool
                If there were no errors
            False : bool
                If there were errors
        '''

        print(f"Creating the '{self.table}' table...")

        # Build a valid SQL 'CREATE TABLE' command
        sql_string = f'CREATE TABLE {self.table} ('
        for field in fields:
            sql_string += field + ' ' + fields[field] + ','
        sql_string = sql_string.rstrip(',') + ')'

        # Attempt to connect to the SQL server
        try:
            self.cursor.execute(sql_string)

        # If there's a problem, print errors and quit
        except pymssql.ProgrammingError as e:
            if '42S01' in str(e):
                print(f"The '{self.table}' table already exists")
            else:
                print(
                    (f"Programming error: {e}. "
                     "Check that there are no typos in the SQL syntax")
                )
            return False

        except Exception as e:
            print(f"SQL execution error: {e}")
            return False

        # Commit the SQL changes
        try:
            self.conn.commit()

        # Handle errors
        except Exception as e:
            print(f"SQL commit error: {e}")
            return False

        return True

    def add(
        self,
        fields: dict[str, str],
    ) -> bool:
        '''
        Add an entry to the database

        Args:
            fields : dict
                A dictionary that includes named fields and values to write

        Raises:
            Exception
                If there were errors writing to the database

        Returns:
            True : boolean
                If the write was successful
            False : boolean
                If the write failed
        '''

        # We need columns and values
        #   Both are strings, a comma separates each entry
        # Create empty strings for columns and corresponding values
        columns = ''
        values = ''

        # Populate the columns and values (comma after each entry)
        for field in fields:
            columns += field + ', '
            values += f"\'{str(fields[field])}\', "

        # Clean up the trailing comma, to make this valid
        columns = columns.strip(", ")
        values = values.strip(", ")

        # Build the SQL command as a string
        sql_string = f'INSERT INTO {self.table} ('
        sql_string += columns
        sql_string += ')'

        sql_string += '\nVALUES '
        sql_string += f'({values});'

        # Try to execute the SQL command (add rows)
        try:
            self.cursor.execute(sql_string)

        except Exception as err:
            if 'Violation of PRIMARY KEY constraint' in str(err):
                print("Error: This primary key already exists")
            else:
                print(f"SQL execution error: {err}")
                print(f"attempted to write:\n{fields}")
                print(sql_string)
            return False

        # Commit the transaction
        try:
            self.conn.commit()
        except Exception as err:
            print(f"SQL commit error: {err}")
            return False

        # If all was good, return True
        return True

    def read(
        self,
        field: str,
        value: str,
    ) -> list | None | bool:
        '''
        Read an entry from the database
        Leave field and value empty to read all entries

        Args:
            field : str
                The field to look in (usually ID)
            value : str
                The value to look for (perhaps a UUID)

        Raises:
            Exception
                If there were errors reading from the database

        Returns:
            entry : list
                A list of entries
                Each entry is a pymssql.Row object
            None :
                If there was no match
            False : boolean
                If the read failed
        '''

        # Build the SQL string
        sql_string = "SELECT *\n"
        sql_string += f"FROM [{self.db}].[dbo].[{self.table}]"

        if field == '':
            sql_string += ';'
        else:
            sql_string += '\n'
            sql_string += f"WHERE {field} = \'{value}\';"

        # Send the SQL command to the server and execute
        entry = []
        try:
            self.cursor.execute(sql_string)
            for row in self.cursor:
                entry.append(row)

        # If there was a problem reading
        except Exception as err:
            if '42S02' in str(err):
                print("Invalid object")
                print("Check the table name is correct")
            else:
                print(f"SQL read error: {err}")
            return False

        # If it all worked, return the entry
        return entry

    def update(
        self,
        field: str,
        value: str,
        body: dict[str, str]
    ) -> str | None | bool:
        '''
        Update an entry in the database

        Parameters:
            field : str
                The field to look in (usually an ID)
            value : str
                The value to look for (usually a UUID)
            body : dict
                Values to update

        Raises:
            Exception
                If there were errors reading from the database

        Returns:
            entry : str
                The entry, it it was found
            None :
                If there was no match
            False : boolean
                If the read failed
        '''

        # Build the UPDATE command
        sql_string = f"UPDATE [{self.db}].[dbo].[{self.table}]\n"

        # Build the SET command
        sql_string += "SET "
        for entry in body:
            sql_string += f"{entry} = \'{body[entry]}\', "

        # Clean up the SET command
        sql_string = sql_string.strip(", ")
        sql_string += '\n'

        # Build the WHERE command
        sql_string += f"WHERE {field} = \'{value}\';"

        # Try updating the entry
        try:
            self.cursor.execute(sql_string)

        # If there was a problem updating
        except Exception as err:
            print(f"SQL read error: {err}")
            return False

        # Commit the transaction
        try:
            self.conn.commit()
        except Exception as err:
            print(f"SQL commit error: {err}")
            return False

        # If it all worked
        return True

    def delete(
        self,
        field: str,
        value: str,
    ) -> bool:
        '''
        Delete an entry from the database

        Args:
            field : str
                The field to search by
            value : str
                The value in the field to find

        Raises:
            Exception
                If there were errors deleting from the database

        Returns:
            True : boolean
                If the write was successful
            False : boolean
                If the write failed
        '''

        # Build the SQL string
        sql_string = f'DELETE FROM {self.table}\n'
        sql_string += f'WHERE {field} = \'{value}\';'

        # Try to execute the SQL command (add rows)
        try:
            self.cursor.execute(sql_string)

        except Exception as err:
            print(f"SQL execution error: {err}")
            return False

        # Commit the transaction
        try:
            self.conn.commit()

        except Exception as err:
            print(f"SQL commit error: {err}")
            return False

        # If all was good, return True
        return True
