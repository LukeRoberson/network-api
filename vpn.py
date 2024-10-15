'''
Classes to manage IPSec VPNs

Each managed VPN:
    * Is stored in an SQL database.
    * Has an object to represent it

When starting up the database is read, and objects are created
When adding a VPN, an object is created and details are written to the database
When editing, the object is updated and the database is updated
'''


from config_parse import AppSettings, config
from sql import SqlServer
from colorama import Fore, Style


class ManagedVPN:
    '''
    Class to manage individual VPNs

    Methods:
        __init__():
            Constructor
        __str__():
            String representation of the VPN
        update_db():
            Update the database with the current object
    '''

    def __init__(
        self,
        name: str,
        endpoint_a: str,
        destination_a: str,
        firewall_a: str,
        inside_nat_a: str,
        outside_nat_a: str,
        endpoint_b_type: str,
        endpoint_b: str,
        cloud_b: str,
        destination_b: str,
        firewall_b: str,
        inside_nat_b: str,
        outside_nat_b: str,
    ) -> None:
        '''
        Constructor

        Parameters:
            name: str (required)
                Friendly name of the VPN

            endpoint_a: str (required)
                Device at endpoint A
            destination_a: str (required)
                Destination IP of tunnel on endpoint A
            firewall_a: str (optional)
                Managed firewall at endpoint A (if any)
            inside_nat_a: str (optional)
                Real IP of endpoint A, before NAT
            outside_nat_a: str (optional)
                Public IP of endpoint A, after NAT

            endpoint_b_type: str (required)
                Type of device at endpoint B (managed, or unmanaged)
            endpoint_b: str (optional)
                Device at endpoint B, if managed
            cloud_b: str (optional)
                The IP of cloud VPN, if unmanaged
            destination_b: str (required)
                Destination IP of tunnel on endpoint B
            firewall_b: str (optional)
                Managed firewall at endpoint B (if any)
            inside_nat_b: str (optional)
                Real IP of endpoint B, before NAT
            outside_nat_b: str (optional)
                Public IP of endpoint B, after NAT
        '''

        # General details
        self.name = name
        self.table = 'tunnels'

        # Endpoint A
        self.a_device = endpoint_a
        self.a_dest = destination_a
        self.a_fw = firewall_a
        self.a_inside_nat = inside_nat_a
        self.a_outside_nat = outside_nat_a

        # Endpoint B
        self.b_type = endpoint_b_type
        self.b_device = endpoint_b
        self.b_cloud = cloud_b
        self.b_dest = destination_b
        self.b_fw = firewall_b
        self.b_inside_nat = inside_nat_b
        self.b_outside_nat = outside_nat_b

        # Dictionaries to store additional details
        self.vpn_a = {}
        self.vpn_b = {}
        self.fw_a = {}
        self.fw_b = {}

    def __str__(
        self
    ) -> str:
        '''
        String representation of the VPN
        '''

        return self.name

    def update_db(
        self
    ) -> None:
        '''
        Update the database with the current object
        '''

        # Connection settings
        settings = AppSettings()

        # SQL query to see if the VPN exists
        with SqlServer(
            server=settings.sql_server,
            database=settings.sql_database,
            table=self.table,
            config=config
        ) as sql:
            output = sql.read(
                field='tunnel_name',
                value=self.name,
            )

        # If entry exists, handle updating
        if output:
            print("VPN already exists in the database")
            print(output)

        # If entry does not exist, handle adding
        else:
            print(
                Fore.GREEN,
                f"Adding {self.name} to the database",
                Style.RESET_ALL
            )

            with SqlServer(
                server=settings.sql_server,
                database=settings.sql_database,
                table=self.table,
                config=config
            ) as sql:
                result = sql.add(
                    fields={
                        'tunnel_name': self.name,
                        'A_endpoint_id': self.a_device,
                        'A_dest_ip': self.a_dest,
                        'A_fw_id': self.a_fw,
                        'A_fw_nat_inside': self.a_inside_nat,
                        'A_fw_nat_outside': self.a_outside_nat,
                        'B_type': self.b_type,
                        'B_endpoint_id': self.b_device,
                        'B_cloud_ip': self.b_cloud,
                        'B_dest_ip': self.b_dest,
                        'B_fw_id': self.b_fw,
                        'B_fw_nat_inside': self.b_inside_nat,
                        'B_fw_nat_outside': self.b_outside_nat,
                    }
                )

            if result:
                print("VPN added successfully")


class VPNManager:
    '''
    Class to manage all VPNs
    Uses ManagedVPN objects

    Methods:
        __init__():
            Constructor
        __len__():
            Return the number of VPNs
        __iter__():
            Iterate through the VPN
        __next__():
            Get the next VPN
        load_vpn():
            Load VPNs from the database
            Used on startup or refresh
        add_vpn():
            Define a new VPN
            Used when adding a VPN
    '''

    def __init__(
        self
    ) -> None:
        '''
        Constructor
        '''

        # Track all ManagedVpn objects
        self.vpn_list = []
        self.table = 'tunnels'

    def __len__(
        self
    ) -> int:
        '''
        Return the number of VPNs
        '''

        return len(self.vpn_list)

    def __iter__(
        self
    ) -> ManagedVPN:
        '''
        Iterate through the VPNs
        '''

        self._index = 0
        return self

    def __next__(
        self
    ) -> ManagedVPN:
        '''
        Get the next VPN
        '''

        if self._index < len(self.vpn_list):
            result = self.vpn_list[self._index]
            self._index += 1
            return result
        else:
            raise StopIteration

    def load_vpn(
        self
    ) -> None:
        '''
        Load VPNs from the database
        '''

        settings = AppSettings()

        with SqlServer(
            server=settings.sql_server,
            database=settings.sql_database,
            table=self.table,
            config=config
        ) as sql:
            output = sql.read(
                field='',
                value='',
            )

        for vpn in output:
            name = vpn[0]
            endpoint_a = vpn[1]
            destination_a = vpn[2]
            a_fw_device = vpn[3]
            a_inside_nat = vpn[4]
            a_outside_nat = vpn[5]
            b_type = vpn[6]
            endpoint_b = vpn[7]
            cloud_b = vpn[8]
            destination_b = vpn[9]
            b_fw_device = vpn[10]
            b_inside_nat = vpn[11]
            b_outside_nat = vpn[12]

            # Create a new ManagedVPN object
            new_vpn = ManagedVPN(
                name=name,
                endpoint_a=endpoint_a,
                destination_a=destination_a,
                firewall_a=a_fw_device,
                inside_nat_a=a_inside_nat,
                outside_nat_a=a_outside_nat,
                endpoint_b_type=b_type,
                endpoint_b=endpoint_b,
                cloud_b=cloud_b,
                destination_b=destination_b,
                firewall_b=b_fw_device,
                inside_nat_b=b_inside_nat,
                outside_nat_b=b_outside_nat,
            )

            # Add the new VPN to the list
            self.vpn_list.append(new_vpn)

    def add_vpn(
        self,
        data: dict,
    ) -> None:
        '''
        Define a new VPN

        A dict of VPN details is passed here from the API
        A ManagedVPN object is created and added to the list

        Parameters:
            data: dict (required)
                Details of the VPN
        '''

        # Get mandatory details
        name = data['addTunnelName']
        endpoint_a = data['addEndpointA']
        destination_a = data['addTunnelDestA']

        # Managed firewall at endpoint A
        if data['addFirewallAEnable'] == 'on':
            a_fw_device = data['addFirewallA']
            a_inside_nat = data['addInsideNatA']
            a_outside_nat = data['addOutsideNatA']
        else:
            a_fw_device = None
            a_inside_nat = None
            a_outside_nat = None

        # Get details of endpoint B
        if data['addEndpointBManaged'] == 'managed':
            b_type = True
            endpoint_b = data['addEndpointB']
            cloud_b = None
            destination_b = data['addTunnelDestB']
        else:
            b_type = False
            endpoint_b = None
            cloud_b = data['addCloudIpB']
            destination_b = None

        # Managed firewall at endpoint B
        if data['addFirewallBEnable'] == 'on':
            b_fw_device = data['addFirewallB']
            b_inside_nat = data['addInsideNatB']
            b_outside_nat = data['addOutsideNatB']
        else:
            b_fw_device = None
            b_inside_nat = None
            b_outside_nat = None

        # Create a new ManagedVPN object
        new_vpn = ManagedVPN(
            name=name,
            endpoint_a=endpoint_a,
            destination_a=destination_a,
            firewall_a=a_fw_device,
            inside_nat_a=a_inside_nat,
            outside_nat_a=a_outside_nat,
            endpoint_b_type=b_type,
            endpoint_b=endpoint_b,
            cloud_b=cloud_b,
            destination_b=destination_b,
            firewall_b=b_fw_device,
            inside_nat_b=b_inside_nat,
            outside_nat_b=b_outside_nat,
        )

        # Add the new VPN to the list
        self.vpn_list.append(new_vpn)
        new_vpn.update_db()

    def delete_vpn(
        self,
        name: str,
    ) -> bool:
        '''
        Delete a managed VPN

        NOTE: This does not remove VPN settings from a device
            This removes the managed VPN from the database

        Parameters:
            name: str (required)
                Name of the VPN to delete

        Returns:
            bool
                True if the VPN was found and deleted
                False if the VPN was not found
        '''

        # Find the vpn in the list
        for vpn in self.vpn_list:
            if vpn.name == name:
                # Delete the device from the database, based on the ID
                with SqlServer(
                    server=config.sql_server,
                    database=config.sql_database,
                    table=self.table,
                    config=config,
                ) as sql:
                    result = sql.delete(
                        field='tunnel_name',
                        value=name,
                    )

                if result:
                    self.vpn_list.remove(vpn)
                    return True

                else:
                    print("Could not delete device from the database.")
                    return False

        # If not found
        return False


# Create a VPNManager object
vpn_manager = VPNManager()
