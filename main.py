import logging
from api.criminalip.cip_request_get_ip import process_ioc
from api.criminalip.manage_files import merge_and_update_ip_addresses, output_result
from api.juniper_networks.utils import load_queries
from config import QUERY_FILE_NAME
from api.juniper_networks.api import check_if_policy_exists, create_address_object, create_address_set, create_security_policy, delete_address_object, delete_address_object_from_address_set

def main():
    queries = load_queries(QUERY_FILE_NAME)
    for c2_name, query_list in queries.data.items():
        process_ioc(c2_name, query_list)
    
    new_ip_addresses, delete_ip_addresses = merge_and_update_ip_addresses()

    if delete_ip_addresses:
        logging.info(f"Deleting address objects for {len(delete_ip_addresses)} malicious IPs")
        ip_list = list(delete_ip_addresses) if isinstance(delete_ip_addresses, set) else delete_ip_addresses
        for ip in ip_list:
            delete_address_object(ip)
        for ip in ip_list:
            delete_address_object_from_address_set(ip)

    if new_ip_addresses:
        logging.info(f"Creating address objects for {len(new_ip_addresses)} new malicious IPs")
        ip_list = list(new_ip_addresses) if isinstance(new_ip_addresses, set) else new_ip_addresses
        for ip in ip_list:
            create_address_object(ip)
        for ip in ip_list:
            create_address_set(ip)
        
    if not check_if_policy_exists():
        create_security_policy()
    else:
        logging.info("Policy already exists, skipping creation")

    output_result(new_ip_addresses)

if __name__ == "__main__":
    main()