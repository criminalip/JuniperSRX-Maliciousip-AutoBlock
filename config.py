import base64
from datetime import datetime, timedelta
import os

BASIC_PATH = os.path.dirname(os.path.abspath(__file__))

# Time information
now = datetime.now()
date = now.strftime("%Y-%m-%d")
yesterday = now - timedelta(days=1)
yesterday_date = yesterday.strftime("%Y-%m-%d")
SEVEN_DAYS_AGO = now - timedelta(days=7)

# Logging information
UPDATEDAY = str(now.strftime("%Y_%m_%d"))
LOG_FILE_NAME = f"{BASIC_PATH}/log/{UPDATEDAY}_log_file.log"

# Important File Paths For Querying IPs and Record Keeping
QUERY_FILE_NAME = f"{BASIC_PATH}/cip_c2_detect_query.json"
CSV_FILE_PATH = f"{BASIC_PATH}/api/input/detect_IP_{date}.csv"
PREVIOUS_CSV_FILE_PATH = f"{BASIC_PATH}/api/input/previous_ip_addresses.csv"
TODAY_CSV_FILE_PATH =  f"{BASIC_PATH}/api/input/today_ip_addresses.csv"
OUTPUT_FILE_PATH = f"{BASIC_PATH}/api/output/detect_IP_{date}.csv"

# SRX API
VSRX_IP = ""
VSRX_PORT = ""
API_USER = ""
API_PASSWORD = ""
auth_string = f"{API_USER}:{API_PASSWORD}"
auth_base64 = base64.b64encode(auth_string.encode()).decode()
VSRX_HEADERS = {
    "Authorization": f"Basic {auth_base64}",
    "Content-Type": "application/xml",
    "Accept": "application/xml"
}

# CIP API
CRIMINALIP_API_KEY = ""
BASE_URL = "https://api.criminalip.io/"
ENDPOINT = "v1/banner/search"
HEADERS = {"x-api-key": CRIMINALIP_API_KEY, "Cache-Control": "no-cache"}

# Global Set To Keep Track Of IP Addresses
ip_data = set()
