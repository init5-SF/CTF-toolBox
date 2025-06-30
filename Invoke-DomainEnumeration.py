#!/usr/bin/python

# Usage: ./Invoke-DomainEnumeration.py 192.168.194.150 "administrator@bank.local" 'Passw0rd!1'

import socket
import dns.resolver
import re
import argparse
import ssl
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, Tls, SIMPLE
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



def create_ldap_connection(dc_ip, username, password):
    auth_methods = [
        {
            'name': 'NTLM',
            'port': 389,
            'use_ssl': False,
            'auth_type': NTLM,
            'get_info': None,
            'format_username': True
        },
        {
            'name': 'LDAP Simple Bind',
            'port': 389,
            'use_ssl': False,
            'auth_type': SIMPLE,
            'get_info': None,
            'format_username': False
        },
        {
            'name': 'LDAPS',
            'port': 636,
            'use_ssl': True,
            'auth_type': SIMPLE,
            'get_info': None,
            'format_username': False,
            'tls': Tls(validate=ssl.CERT_NONE)
        }
    ]
    print(f" ")
    for method in auth_methods:
        try:
            #print(f"{YELLOW}[!] Attempting {method['name']} authentication...{RESET}")
            
            # Format username if needed (for NTLM)
            auth_user = f"{username.split('@')[0]}\\{username.split('@')[1].split('.')[0]}" \
                      if method['format_username'] and '@' in username else username

            # Create server configuration
            server_args = {
                'host': dc_ip,
                'port': method['port'],
                'use_ssl': method['use_ssl'],
                'get_info': method['get_info'],
                'connect_timeout': 10
            }
            if method.get('tls'):
                server_args['tls'] = method['tls']
            
            server = Server(**server_args)

            # Create connection
            conn_args = {
                'server': server,
                'user': auth_user,
                'password': password,
                'authentication': method['auth_type'],
                'auto_bind': True,
                'receive_timeout': 15,
                'auto_referrals': False,
                'read_only': True
            }
            
            connection = Connection(**conn_args)
            print(f"{GREEN}[!] Successfully bound with {method['name']} authentication{RESET}")
            return connection

        except Exception as e:
            print(f"{RED}[!] {method['name']} authentication failed: {str(e)}{RESET}")
            continue

    raise Exception("All authentication methods failed")


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
        entry = connection.entries[0]
        domain_name = entry['name'].value
        domain_sid = entry['objectSid'].value if 'objectSid' in entry else "N/A"
        domain_dn = entry['distinguishedName'].value
        
        # Convert binary SID to string format if needed
        if isinstance(domain_sid, bytes):
            try:
                import struct
                revision = domain_sid[0]
                sub_authority_count = domain_sid[1]
                identifier_authority = int.from_bytes(domain_sid[2:8], byteorder='big')
                
                sid_format = f'<{sub_authority_count}I'
                sub_authorities = struct.unpack_from(sid_format, domain_sid[8:8+4*sub_authority_count])
                
                domain_sid = f'S-{revision}-{identifier_authority}' + ''.join(f'-{sub_auth}' for sub_auth in sub_authorities)
            except Exception as e:
                print(f"{YELLOW}Warning: Could not convert SID ({e}), using raw value{RESET}")
                domain_sid = str(domain_sid)

        # Handle machine account quota
        machine_account_quota = entry['ms-DS-MachineAccountQuota'].value if 'ms-DS-MachineAccountQuota' in entry else "N/A"
        if machine_account_quota != "N/A":
            try:
                machine_account_quota = int(machine_account_quota)
            except (ValueError, TypeError):
                machine_account_quota = "N/A"

        # Extract the FQDN from the distinguishedName
        fqdn = domain_dn.replace("DC=", "").replace(",", ".")

        print_section_header("Domain Info")
        print(f"Domain Name: {fqdn}")
        print(f"Domain SID: {domain_sid}")
        
        if machine_account_quota == "N/A":
            print(f"Machine Account Quota: {machine_account_quota}")
        else:
            status_color = RED if machine_account_quota > 0 else RESET
            print(f"Machine Account Quota: {status_color}{machine_account_quota}{RESET}")
            
        return domain_sid
    else:
        print("Domain information not found.")
        return None


def list_ad_trusts(connection, base_dn):
    try:
        print_section_header("Active Directory Trusts")
        
        filter_str_trusts = "(objectClass=trustedDomain)"
        attributes_trusts = [
            'name', 
            'trustPartner', 
            'trustType', 
            'trustAttributes', 
            'trustDirection', 
            'securityIdentifier'
        ]
        trusts_search_base = f"CN=System,{base_dn}"
        trusts = ldap_search(connection, trusts_search_base, filter_str_trusts, attributes_trusts)
        
        if not trusts:
            print("No Active Directory trusts found.")
            return
            
        # Get current DC IP from connection
        dc_ip = connection.server.host
        
        # Create a resolver and set nameserver to current DC IP
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dc_ip]
        resolver.timeout = 3
        resolver.lifetime = 5

        for trust in trusts:
            source_name = base_dn.replace("DC=", "").replace(",", ".")
            target_name = trust['name'].value
            trust_partner = trust['trustPartner'].value if 'trustPartner' in trust else target_name
            
            trust_type = int(trust['trustType'].value) if 'trustType' in trust else None
            if trust_type == 1:
                trust_type_str = "WINDOWS_NON_ACTIVE_DIRECTORY"
            elif trust_type == 2:
                trust_type_str = "WINDOWS_ACTIVE_DIRECTORY"
            elif trust_type == 3:
                trust_type_str = "MIT"
            else:
                trust_type_str = f"UNKNOWN ({trust_type})"
            
            trust_attrs = int(trust['trustAttributes'].value) if 'trustAttributes' in trust else 0
            attribute_flags = []
            if trust_attrs & 0x1: attribute_flags.append("NON_TRANSITIVE")
            if trust_attrs & 0x2: attribute_flags.append("UPLEVEL_ONLY")
            if trust_attrs & 0x4: attribute_flags.append("QUARANTINED_DOMAIN")
            if trust_attrs & 0x8: attribute_flags.append("FOREST_TRANSITIVE (Forest-wide Authentication)")
            if trust_attrs & 0x10: attribute_flags.append("CROSS_ORGANIZATION (Selective Authentication)")
            if trust_attrs & 0x20: attribute_flags.append("WITHIN_FOREST")
            if trust_attrs & 0x40: attribute_flags.append("TREAT_AS_EXTERNAL")
            if trust_attrs & 0x80: attribute_flags.append("USES_RC4_ENCRYPTION")
            if trust_attrs & 0x200: attribute_flags.append("CROSS_ORGANIZATION_NO_TGT_DELEGATION")
            if trust_attrs & 0x800: attribute_flags.append("CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION")
            if not attribute_flags:
                attribute_flags.append("NONE")
            trust_attrs_str = " | ".join(attribute_flags)
            
            trust_dir = int(trust['trustDirection'].value) if 'trustDirection' in trust else 0
            if trust_dir == 0:
                trust_dir_str = "DISABLED"
            elif trust_dir == 1:
                trust_dir_str = "Inbound"
            elif trust_dir == 2:
                trust_dir_str = "Outbound"
            elif trust_dir == 3:
                trust_dir_str = "Bidirectional"
            else:
                trust_dir_str = f"UNKNOWN ({trust_dir})"
            
            trust_sid = "N/A"
            if 'securityIdentifier' in trust:
                sid_value = trust['securityIdentifier'].value

                # Convert str to bytes if needed
                if isinstance(sid_value, str):
                    sid_value = sid_value.encode('utf-8', 'surrogateescape')

                if isinstance(sid_value, bytes) and len(sid_value) >= 8:
                    try:
                        import struct
                        revision = sid_value[0]
                        sub_authority_count = sid_value[1]
                        identifier_authority = int.from_bytes(sid_value[2:8], byteorder='big')

                        max_possible = (len(sid_value) - 8) // 4
                        actual_subs = min(sub_authority_count, max_possible)

                        if actual_subs >= 1:
                            sid_format = f'<{actual_subs}I'
                            sub_authorities = struct.unpack_from(sid_format, sid_value[8:8 + 4 * actual_subs])

                            trust_sid = f'S-{revision}-{identifier_authority}' + ''.join(f'-{sub_auth}' for sub_auth in sub_authorities)
                        else:
                            trust_sid = "Invalid SID (no sub-authorities)"
                    except Exception as e:
                        trust_sid = f"Could not convert SID ({e})"
                else:
                    trust_sid = "N/A"


          
            print(f"{GREEN}SourceName      : {source_name}{RESET}")
            print(f"{GREEN}TargetName      : {trust_partner} ({target_name}){RESET}")
            print(f"TrustType       : {trust_type_str}")
            print(f"{RED}TrustAttributes : {trust_attrs_str}{RESET}")
            print(f"TrustDirection  : {trust_dir_str}")
            print(f"TrustSID        : {trust_sid}")
            print("")
            
            # Enumerate DCs using NS records via DC DNS
            print(f"{CYAN}Enumerating DCs for domain: {trust_partner}{RESET}")
            found_dcs = False
            try:
                ns_records = resolver.resolve(trust_partner, 'NS')
                print(f"{GREEN}[+] Domain Controllers in {trust_partner}{RESET}")
                for ns in ns_records:
                    dc_name = ns.target.to_text().rstrip('.')
                    try:
                        a_records = resolver.resolve(dc_name, 'A')
                        for a in a_records:
                            ip = a.to_text()
                            print(f"  - {dc_name} ({ip})")
                            found_dcs = True
                    except dns.resolver.NoAnswer:
                        print(f"  - {dc_name} (No A record found)")
                    except dns.resolver.NXDOMAIN:
                        print(f"  - {dc_name} (NXDOMAIN)")
                    except Exception as e:
                        print(f"  - {dc_name} (Error resolving A: {e})")
            except dns.resolver.NoAnswer:
                print(f"{YELLOW}No NS records found for {trust_partner}{RESET}")
            except dns.resolver.NXDOMAIN:
                print(f"{YELLOW}Domain does not exist: {trust_partner}{RESET}")
            except Exception as e:
                print(f"{YELLOW}Error resolving NS records for {trust_partner}: {e}{RESET}")

            if not found_dcs:
                print(f"[!] Could not find any Domain Controllers for '{trust_partner}'")
            
            print("")
            
    except Exception as e:
        print(f"{RED}Error enumerating AD trusts: {e}{RESET}")



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
    attributes_users = ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 'scriptPath']
    users = ldap_search(connection, base_dn, filter_str_users, attributes_users)

    print_section_header("All Domain Users")
    for user in users:
        print(f"samAccountName: {user['sAMAccountName'].value}")
        print(f"UPN: {user['userPrincipalName'].value}")
        print(f"DN: {user['distinguishedName'].value}")
        if 'scriptPath' in user and user['scriptPath'].value:
            print(f"Script Path:{RED} {user['scriptPath'].value}{RESET}")
        print(f" ")


def list_computers(connection, base_dn):
    filter_str_computers = "(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
    attributes_computers = ['sAMAccountName', 'distinguishedName', 'operatingSystem']
    computers = ldap_search(connection, base_dn, filter_str_computers, attributes_computers)

    print_section_header("All Domain Computers")
    for computer in computers:
        print(f"Computer: {computer['sAMAccountName'].value}, DN: {computer['distinguishedName'].value}")
        print(f"DN: {computer['distinguishedName'].value}")
        print(f"Platform: {computer['operatingSystem'].value}")
        print(f" ")


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
    attributes_dc = ['sAMAccountName', 'distinguishedName', 'operatingSystem', 'operatingSystemVersion', 'serverReferenceBL']
    dcs = ldap_search(connection, base_dn, filter_str_dc, attributes_dc)

    print_section_header("Domain Controllers")
    for dc in dcs:
        os_name = dc['operatingSystem'].value if 'operatingSystem' in dc else "Unknown OS"
        os_version = dc['operatingSystemVersion'].value if 'operatingSystemVersion' in dc else "Unknown Version"
        print(f"Domain Controller: {dc['sAMAccountName'].value}")
        print(f"Operating System: {os_name} ({os_version})")
        print(f"DN: {dc['distinguishedName'].value}")
        site = dc['serverReferenceBL'].value  
        match = re.search(r'CN=([^,]+),CN=Sites', site)
        if match:
            site_name = match.group(1)
            print(f"AD Site: {site_name}")
        else:
            print("AD Site: Not found")
        print(" ")


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
    parser.add_argument("username", help="Username in format user@domain.com or domain\\user")
    parser.add_argument("password", help="Password for authentication")
    args = parser.parse_args()

    try:
        connection = create_ldap_connection(args.dc_ip, args.username, args.password)
        
        # Extract domain name from the provided username for base_dn
        if '@' in args.username:
            domain_name = args.username.split('@')[-1]
            base_dn = ",".join([f"DC={component}" for component in domain_name.split('.')])
            # Get RootDSE information if possible
            try:
                root_dse = connection.server.info
                config_nc = root_dse.other['configurationNamingContext'][0]
            except:
                #print(f"{YELLOW}Could not get RootDSE information, using domain from username{RESET}")
                config_nc = f"CN=Configuration,{base_dn}"
        else:
            # For NetBIOS format, we must get the domain from RootDSE
            try:
                root_dse = connection.server.info
                domain_name = root_dse.other['defaultNamingContext'][0].replace('DC=','').replace(',','.')
                base_dn = ",".join([f"DC={component}" for component in domain_name.split('.')])
                config_nc = root_dse.other['configurationNamingContext'][0]
            except Exception as e:
                print(f"{RED}Fatal error: Could not get domain information from RootDSE when using NetBIOS format{RESET}")
                print(f"{RED}Please try using UPN format (user@domain.com) instead{RESET}")
                connection.unbind()
                exit(1)

        # Display domain and CA information
        get_domain_info(connection, base_dn)
        list_ad_trusts(connection, base_dn)
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
        
    except Exception as e:
        print(f"{RED}[!] Fatal error: {e}{RESET}")
        exit(1)


if __name__ == "__main__":
    main()
