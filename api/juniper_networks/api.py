"""
Juniper Firewall Configuration 

This module provides functions to programmatically manage Juniper firewall configurations
using NETCONF/XML-RPC. It enables automating the creation and management of security
objects, address sets, and security policies.

Dependencies:
    - logging: For operation logging
    - xml.etree.ElementTree: For XML parsing
    - .utils: Contains the make_rpc_request function for NETCONF communication
"""
import logging
from .utils import make_rpc_request
import xml.etree.ElementTree as ET

def commit_configuration():
    """Commit the configuration changes"""
    logging.info("Committing configuration changes")
    
    xml_data = """
    <commit-configuration/>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 204]:
        logging.info("Successfully committed configuration")
        return True
    else:
        if response:
            logging.error(f"Failed to commit configuration: {response.text}")
        return False


def create_address_object(ip_address):
    """Create an address object for a malicious IP"""
    logging.info(f"Creating address object for IP: {ip_address}")
    
    address_name = f"test-ip-{ip_address.replace('.', '-')}"
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <address-book>
                        <name>global</name>
                        <address>
                            <name>{address_name}</name>
                            <ip-prefix>{ip_address}/32</ip-prefix>
                        </address>
                    </address-book>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully created address object for {ip_address}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to create address object: {response.text}")
        return False


def create_address_set(ip_address, address_set_name="test-deny-set"):
    """Create an address set containing malicious IPs"""
    address_name = f"test-ip-{ip_address.replace('.', '-')}"
    
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <address-book>
                        <name>global</name>
                        <address-set>
                            <name>{address_set_name}</name>
                            <address>
                                <name>{address_name}</name>
                            </address>
                        </address-set>
                    </address-book>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully created address set {address_set_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to create address set: {response.text}")
        return False


def create_security_policy(policy_name="deny-to-test-set", address_set_name="test-deny-set", from_zone="trust", to_zone="untrust"):
    """Create a security policy to block traffic in a specific direction"""
    logging.info(f"Creating security policy: {policy_name}")
    
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <policies>
                        <policy>
                            <from-zone-name>{from_zone}</from-zone-name>
                            <to-zone-name>{to_zone}</to-zone-name>
                            <policy>
                                <name>{policy_name}</name>
                                <match>
                                    <source-address>any</source-address>
                                    <destination-address>{address_set_name}</destination-address>
                                    <application>any</application>
                                </match>
                                <then>
                                    <deny/>
                                    <log>
                                        <session-init/>
                                    </log>
                                </then>
                            </policy>
                        </policy>
                    </policies>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully created security policy {policy_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to create security policy: {response.text}")
        return False


def create_permit_security_policy(policy_name, address_set_name, from_zone, to_zone):
    """Create a security policy to allow traffic in a specific direction"""
    logging.info(f"Creating permit security policy: {policy_name}")
    
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <policies>
                        <policy>
                            <from-zone-name>{from_zone}</from-zone-name>
                            <to-zone-name>{to_zone}</to-zone-name>
                            <policy>
                                <name>{policy_name}</name>
                                <match>
                                    <source-address>any</source-address>
                                    <destination-address>{address_set_name}</destination-address>
                                    <application>any</application>
                                </match>
                                <then>
                                    <permit/>
                                    <log>
                                        <session-init/>
                                    </log>
                                </then>
                            </policy>
                        </policy>
                    </policies>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully created permit security policy {policy_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to create permit security policy: {response.text}")
        return False


def delete_address_object(ip_address):
    """Delete an address object for a specific IP"""
    address_name = f"test-ip-{ip_address.replace('.', '-')}"

    logging.info(f"Deleting address object: {address_name}")

    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <address-book>
                        <name>global</name>
                        <address operation="delete">
                            <name>{address_name}</name>
                        </address>
                    </address-book>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully deleted address object {address_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to delete address object: {response.text}")
        return False


def delete_address_set(set_name):
    """Delete an address set"""
    logging.info(f"Deleting address set: {set_name}")
    
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <address-book>
                        <name>global</name>
                        <address-set operation="delete">
                            <name>{set_name}</name>
                        </address-set>
                    </address-book>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully deleted address set {set_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to delete address set: {response.text}")
        return False


def delete_all_address_objects(address_book_name="global"):
    """Delete all malicious IP address objects from the address book"""
    logging.info(f"Deleting all malicious IP address objects from address book: {address_book_name}")
  
    # Get all address sets to remove references
    xml_data = f"""
    <get-configuration>
        <configuration>
            <security>
                <address-book>
                    <name>{address_book_name}</name>
                </address-book>
            </security>
        </configuration>
    </get-configuration>
    """
    response = make_rpc_request(xml_data)
    if response and response.status_code == 200:
        text = response.text
        
        # Clean up the response text if needed
        if text.startswith('--'):
            xml_start = text.find("<configuration")
            if xml_start != -1:
                boundary_marker = text[:text.find('\n')]
                xml_end = text.rfind(boundary_marker)
                if xml_end != -1:
                    text = text[xml_start:xml_end].strip()
        try:
            root = ET.fromstring(text)
            for addr in root.findall(".//address/name"):
                if addr.text and addr.text.startswith("malicious-"):
                    ip_parts = addr.text.replace('malicious-', '').split('-')
                    ip_address = '.'.join(ip_parts)
                    delete_address_object(ip_address)
            return True
        except Exception as e:
            logging.error(f"Error processing address sets: {str(e)}")
            return False


def delete_address_object_from_address_set(ip_address, address_set_name="test-deny-set"):
    """Remove a specific IP address reference from an address set"""
    address_name = f"test-ip-{ip_address.replace('.', '-')}"

    logging.info(f"Removing address {address_name} from address set {address_set_name}")
    
    xml_data = f"""
    <edit-config>
        <target>
            <candidate/>
        </target>
        <config>
            <configuration>
                <security>
                    <address-book>
                        <name>global</name>
                        <address-set>
                            <name>{address_set_name}</name>
                            <address operation="delete">
                                <name>{address_name}</name>
                            </address>
                        </address-set>
                    </address-book>
                </security>
            </configuration>
        </config>
    </edit-config>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code in [200, 201, 204]:
        logging.info(f"Successfully removed address {address_name} from set {address_set_name}")
        commit_configuration()
        return True
    else:
        if response:
            logging.error(f"Failed to remove address from set: {response.text}")
        return False


def check_if_policy_exists(policy_name="deny-to-test-set", from_zone="trust", to_zone="untrust"):
    """Check if a security policy with the given name exists in the specified zone pair"""
    logging.info(f"Checking if policy {policy_name} exists (from {from_zone} to {to_zone})")
    
    xml_data = f"""
    <get-configuration>
        <configuration>
            <security>
                <policies>
                    <policy>
                        <from-zone-name>{from_zone}</from-zone-name>
                        <to-zone-name>{to_zone}</to-zone-name>
                    </policy>
                </policies>
            </security>
        </configuration>
    </get-configuration>
    """
    
    response = make_rpc_request(xml_data)
    if response and response.status_code == 200:
        text = response.text
        
        # Clean up the response text if needed
        if text.startswith('--'):
            xml_start = text.find("<configuration")
            if xml_start != -1:
                boundary_marker = text[:text.find('\n')]
                xml_end = text.rfind(boundary_marker)
                if xml_end != -1:
                    text = text[xml_start:xml_end].strip()
        try:
            root = ET.fromstring(text)
            # Find all the policy names and check if our policy exists.
            for policy_elem in root.findall(".//policy/name"):
                if policy_elem.text and policy_elem.text == policy_name:
                    logging.info(f"Policy {policy_name} exists in zone pair {from_zone}-{to_zone}")
                    return True
            
            logging.info(f"Policy {policy_name} does not exist in zone pair {from_zone}-{to_zone}")
            return False
        except Exception as e:
            logging.error(f"Error checking if policy exists: {str(e)}")
            return False
    else:
        if response:
            logging.error(f"Failed to check if policy exists: {response.text}")
        return False
