import logging
import requests
from api.criminalip.manage_files import QueryData
from config import VSRX_IP, VSRX_PORT, VSRX_HEADERS

def load_queries(query_file_name):
    """Read the c2 detect query json file"""
    return QueryData.from_file(query_file_name)

def make_rpc_request(rpc_xml):
    """Make an RPC request to the vSRX REST API"""
    url = f"http://{VSRX_IP}:{VSRX_PORT}/rpc"
    logging.info(f"Making RPC request to {url}")
    
    try:
        response = requests.post(url, headers=VSRX_HEADERS, data=rpc_xml, verify=False)
        logging.info(f"Response status: {response.status_code}")
        return response
    except Exception as e:
        logging.error(f"API request failed: {str(e)}")
        return None


   