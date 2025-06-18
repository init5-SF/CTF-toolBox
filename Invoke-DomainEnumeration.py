#!/usr/bin/python

# Usage: ./Invoke-DomainEnumeration.py 192.168.194.150 "administrator@bank.local" 'Passw0rd!1'

import argparse
from ldap3 import Server, Connection, ALL, NTLM
import requests

# Color aliases
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"



def ldap_search(connection, base_dn, filter_str, attributes=None):
    if attributes is None:
        attributes = ALL
    connection.search(base_dn, filter_str, attributes=attributes)
    return connection.entries


def print_section_header(header):
    # Define the width of the header (40 characters)
    width = 40
    # Center the header text within the width
    centered_header = header.center(width)
    # Print the header with centered text
    print("\n" + "-" * width)
    print(f"{CYAN}{centered_header}{RESET}")
    print("-" * width)


def get_domain_info(connection, base_dn):
    # Query RootDSE for domain and forest information
    connection.search(base_dn, '(objectClass=domain)', attributes=['name', 'objectSid', 'distinguishedName', 'ms-DS-MachineAccountQuota'])
    if connection.entries:
        domain_name = connection.entries[0]['name'].value
        domain_sid = connection.entries[0]['objectSid'].value
        domain_dn = connection.entries[0]['distinguishedName'].value
        machine_account_quota = connection.entries[0]['ms-DS-MachineAccountQuota'].value if 'ms-DS-MachineAccountQuota' in connection.entries[0] else "N/A"

        # Extract the FQDN from the distinguishedName
        fqdn = domain_dn.replace("DC=", "").replace(",", ".")

        print_section_header("Domain Info")
        print(f"Domain Name: {fqdn}")
        print(f"Domain SID: {domain_sid}")
        print(f"Machine Account Quota: {RED + str(machine_account_quota) + RESET if machine_account_quota > 0 else machine_account_quota}")
        return domain_sid
    else:
        print("Domain information not found.")
        return None


def get_enterprise_ca(connection, config_nc):
    # Query for Enterprise CA
    print_section_header("ADCS Info")
    ca_search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"
    connection.search(ca_search_base, '(objectClass=pKIEnrollmentService)', attributes=['name', 'dNSHostName'])
    
    if connection.entries:
        for entry in connection.entries:
            ca_name = entry['name'].value
            ca_hostname = entry['dNSHostName'].value if 'dNSHostName' in entry else "N/A"
            print(f"Enterprise CA: {ca_hostname}\\{ca_name}")
            
            # Check for web enrollment
            if ca_hostname != "N/A":
                try:
                    url = f"http://{ca_hostname}/certsrv"
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    
                    if response.status_code in (200, 401):
                        print(f"{GREEN}Web Enrollment: RUNNING (HTTP {response.status_code}){RESET}")
                        print(f"{RED}Relay URL: {url}/certfnsh.asp{RESET}")
                        
                        # Check for NTLM authentication support
                        if 'WWW-Authenticate' in response.headers and 'NTLM' in response.headers['WWW-Authenticate']:
                            print(f"{RED}NTLM Authentication: ENABLED{RESET}")
                        else:
                            print("NTLM Authentication: DISABLED")
                    #else:
                        #print(f"Web Enrollment is NOT running (HTTP {response.status_code})")
                        
                except requests.exceptions.RequestException as e:
                    print(f"{YELLOW}Could not check Web Enrollment: {e}{RESET}")
    else:
        print("Enterprise CA not found.")



def list_users(connection, base_dn):
    filter_str_users = "(objectClass=user)"
    attributes_users = ['sAMAccountName', 'userPrincipalName', 'distinguishedName']
    users = ldap_search(connection, base_dn, filter_str_users, attributes_users)

    print_section_header("All Domain Users")
    for user in users:
        print(f"Username: {user['sAMAccountName'].value}, UPN: {user['userPrincipalName'].value}, DN: {user['distinguishedName'].value}")


def list_computers(connection, base_dn):
    filter_str_computers = "(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
    attributes_computers = ['sAMAccountName', 'distinguishedName']
    computers = ldap_search(connection, base_dn, filter_str_computers, attributes_computers)

    print_section_header("All Domain Computers")
    for computer in computers:
        print(f"Computer: {computer['sAMAccountName'].value}, DN: {computer['distinguishedName'].value}")


def list_managed_service_accounts(connection, base_dn):
    # Updated filter to match either msDS-GroupManagedServiceAccount or msDS-ManagedServiceAccount
    filter_str_managed = "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
    attributes_managed = ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 'description', 'objectClass']
    managed_accounts = ldap_search(connection, base_dn, filter_str_managed, attributes_managed)

    print_section_header("Managed Service Accounts")
    for account in managed_accounts:
        # Safely access the sAMAccountName attribute
        sam_account_name = account['sAMAccountName'].value if 'sAMAccountName' in account else "N/A"
        # Safely access the description attribute
        description = account['description'].value if 'description' in account else "No description available"
        
        # Determine the account type
        if 'msDS-GroupManagedServiceAccount' in account['objectClass'].values:
            account_type = "Group Managed Service Account (gMSA)"
        elif 'msDS-ManagedServiceAccount' in account['objectClass'].values:
            account_type = "Managed Service Account (MSA)"
        else:
            account_type = "Unknown"

        print(f"SAM Account Name: {sam_account_name}")
        print(f"Account Type: {account_type}")
        print(f"Description: {description}")
        print(f" ")


def list_domain_controllers(connection, base_dn):
    filter_str_dc = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
    attributes_dc = ['sAMAccountName', 'distinguishedName', 'operatingSystem', 'operatingSystemVersion']
    dcs = ldap_search(connection, base_dn, filter_str_dc, attributes_dc)

    print_section_header("Domain Controllers")
    for dc in dcs:
        os_name = dc['operatingSystem'].value if 'operatingSystem' in dc else "Unknown OS"
        os_version = dc['operatingSystemVersion'].value if 'operatingSystemVersion' in dc else "Unknown Version"
        print(f"Domain Controller: {dc['sAMAccountName'].value}")
        print(f"Operating System: {os_name} ({os_version})")
        print(f"DN: {dc['distinguishedName'].value}")
        print(" ")  # Add blank line for readability


def list_kerberoastable_users(connection, base_dn):
    filter_str_kerberoastable = "(&(userAccountControl:1.2.840.113556.1.4.803:=512)(servicePrincipalName=*))"
    attributes_kerberoastable = ['sAMAccountName', 'userPrincipalName', 'distinguishedName']
    kerberoastable_users = ldap_search(connection, base_dn, filter_str_kerberoastable, attributes_kerberoastable)

    print_section_header("Kerberoastable Users")
    for user in kerberoastable_users:
        print(f"Username: {user['sAMAccountName'].value}, UPN: {user['userPrincipalName'].value}, DN: {user['distinguishedName'].value}")


def list_asrep_roastable_users(connection, base_dn):
    filter_str_asrep_roastable = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    attributes_asrep_roastable = ["sAMAccountName", "userAccountControl"]

    try:
        asrep_roastable_users = ldap_search(connection, base_dn, filter_str_asrep_roastable, attributes_asrep_roastable)

        if asrep_roastable_users:
            print_section_header("AS-REP Roastable Users")
            for user in asrep_roastable_users:
                # Check if 'userAccountControl' attribute is present and has a valid value
                if 'userAccountControl' in user and user['userAccountControl'].value != '4194304:1':
                    print(f"sAMAccountName: {user.sAMAccountName.value}")
    except Exception as e:
        print(f"Error searching AS-REP Roastable users: {e}")


def list_admincount_equals_1_users(connection, base_dn):
    # Updated filter to match only user objects with adminCount=1
    filter_str_admincount_equals_1 = "(&(objectClass=user)(adminCount=1))"
    attributes_admincount_equals_1 = ['sAMAccountName', 'userPrincipalName', 'distinguishedName']
    admincount_equals_1_users = ldap_search(connection, base_dn, filter_str_admincount_equals_1, attributes_admincount_equals_1)

    print_section_header("Users with adminCount=1")
    for user in admincount_equals_1_users:
        print(f"Username: {user['sAMAccountName'].value}, UPN: {user['userPrincipalName'].value}, DN: {user['distinguishedName'].value}")


def list_users_with_weak_description(connection, base_dn):
    filter_str_weak_description = "(&(objectClass=user)(description=*))"
    attributes_weak_description = ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 'description']
    users_with_weak_description = ldap_search(connection, base_dn, filter_str_weak_description, attributes_weak_description)

    print_section_header("Users with Description")
    for user in users_with_weak_description:
        print(f"SAM Account Name: {user['sAMAccountName'].value}")
        print(f"Description: {user['description'].value}")
        print(f" ")


def list_domain_admins(connection, base_dn):
    filter_str_domain_admins = "(memberOf=CN=Domain Admins,CN=Users," + base_dn + ")"
    attributes_domain_admins = ['sAMAccountName', 'userPrincipalName', 'distinguishedName']
    domain_admins = ldap_search(connection, base_dn, filter_str_domain_admins, attributes_domain_admins)

    print_section_header("Domain Admins")
    for admin in domain_admins:
        print(f"Admin Username: {admin['sAMAccountName'].value}, UPN: {admin['userPrincipalName'].value}, DN: {admin['distinguishedName'].value}")


def list_sccm_instances(connection, base_dn):
    print_section_header("SCCM Info")
    try:
        # Query for SCCM Management Points
        filter_str_sccm = "(objectClass=mSSMSManagementPoint)"
        attributes_sccm = ['dNSHostName']  # Use dNSHostName instead of mssmsmpname
        sccm_instances = ldap_search(connection, base_dn, filter_str_sccm, attributes_sccm)

        if sccm_instances:
            for instance in sccm_instances:
                # Safely access the dNSHostName attribute
                dnshostname = instance['dNSHostName'].value if 'dNSHostName' in instance else "N/A"
                print(f"SCCM Management Point: {dnshostname}")
                print(f" ")
        else:
            print("No SCCM instances found.")
    except Exception as e:
        print("SCCM is not installed or the schema is not extended.")
        print(f"Error: {e}")


def list_constrained_delegation_accounts(connection, base_dn):
    # Query for accounts with constrained delegation
    filter_str_constrained_delegation = "(msDS-AllowedToDelegateTo=*)"
    attributes_constrained_delegation = ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 'msDS-AllowedToDelegateTo']
    constrained_delegation_accounts = ldap_search(connection, base_dn, filter_str_constrained_delegation, attributes_constrained_delegation)

    print_section_header("Accounts with Constrained Delegation")
    
    # First get all computer names in the domain for SPN validation
    computers = set()
    connection.search(base_dn, "(objectClass=computer)", attributes=['sAMAccountName'])
    for computer in connection.entries:
        computers.add(computer['sAMAccountName'].value.rstrip('$').upper())

    for account in constrained_delegation_accounts:
        print(f"Account: {YELLOW}{account['sAMAccountName'].value}{RESET}")
        print(f"Allowed to Delegate To:")
        
        for spn in account['msDS-AllowedToDelegateTo'].values:
            # Parse the SPN to get the target computer name
            try:
                service, target = spn.split('/', 1)
                computer_name = target.split('.')[0].upper() + "$"  # Add $ to match AD format
                
                # Check if computer exists
                if computer_name.rstrip('$').upper() in computers:
                    print(f"  {GREEN}{spn}{RESET} (Valid)")
                else:
                    print(f"  {RED}{spn}{RESET} {YELLOW}(ORPHANED){RESET}")
            except:
                print(f"  {spn} (Malformed SPN)")
        print(" ")  # Add blank line between accounts
#        print(f" ")


def list_trusted_for_delegation_accounts(connection, base_dn):
    # Query for accounts trusted for delegation
    filter_str_trusted_for_delegation = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    attributes_trusted_for_delegation = ['sAMAccountName', 'userPrincipalName', 'distinguishedName']
    trusted_for_delegation_accounts = ldap_search(connection, base_dn, filter_str_trusted_for_delegation, attributes_trusted_for_delegation)

    print_section_header("Accounts Trusted for Delegation")
    for account in trusted_for_delegation_accounts:
        print(f"Account: {account['sAMAccountName'].value}, UPN: {account['userPrincipalName'].value}, DN: {account['distinguishedName'].value}")


def list_accounts_with_password_attributes(connection, base_dn):
    # Query for accounts with unixUserPassword or userPassword populated
    filter_str_password_attributes = "(|(unixUserPassword=*)(userPassword=*))"
    attributes_password_attributes = ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 'unixUserPassword', 'userPassword']
    accounts_with_password_attributes = ldap_search(connection, base_dn, filter_str_password_attributes, attributes_password_attributes)

    print_section_header("Accounts with Password Attributes")
    for account in accounts_with_password_attributes:
        print(f"Account: {account['sAMAccountName'].value}, UPN: {account['userPrincipalName'].value}, DN: {account['distinguishedName'].value}")
        if 'unixUserPassword' in account:
            print(f"{RED}unixUserPassword: {account['unixUserPassword'].value}{RESET}")
        if 'userPassword' in account:
            print(f"{RED}userPassword: {account['userPassword'].value}{RESET}")
        print(f" ")


def main():
    parser = argparse.ArgumentParser(description="LDAP Enumeration Script")
    parser.add_argument("dc_ip", help="Domain Controller IP address")
    parser.add_argument("username", help="Username for LDAP authentication")
    parser.add_argument("password", help="Password for LDAP authentication")
    args = parser.parse_args()

    # Extract domain name from the provided username
    domain_name = args.username.split('@')[-1]

    base_dn = ",".join([f"DC={component}" for component in domain_name.split('.')])

    server = Server(args.dc_ip, port=389, use_ssl=False, get_info=ALL, connect_timeout=5)
    connection = Connection(server, user=args.username, password=args.password, auto_bind=True)

    # Get RootDSE information
    root_dse = server.info
    config_nc = root_dse.other['configurationNamingContext'][0]

    # Display domain and CA information
    get_domain_info(connection, base_dn)
    get_enterprise_ca(connection, config_nc)
    list_sccm_instances(connection, base_dn)

    # List other objects
    list_users(connection, base_dn)
    list_computers(connection, base_dn)
    list_managed_service_accounts(connection, base_dn)
    list_domain_controllers(connection, base_dn)
    list_kerberoastable_users(connection, base_dn)
    list_asrep_roastable_users(connection, base_dn)
    list_admincount_equals_1_users(connection, base_dn)
    list_users_with_weak_description(connection, base_dn)
    list_domain_admins(connection, base_dn)
    list_constrained_delegation_accounts(connection, base_dn)
    list_trusted_for_delegation_accounts(connection, base_dn)
    list_accounts_with_password_attributes(connection, base_dn)
    print("\n" + "-" * 40)
    # Close the connection
    connection.unbind()


if __name__ == "__main__":
    main()
