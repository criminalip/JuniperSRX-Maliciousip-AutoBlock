# Juniper-SRX-Maliciousip-Autoblock

## Overview

Welcome to Criminal IP Integration with Juniper Networks Firewalls!

This project automates the process of swiftly blocking malicious IP addresses identified by the Criminal IP service using Juniper Network SRX Firewalls. By leveraging Criminal Ip’s real-time threat intelligence, the system retrieves and updates lists of identified malicious IPs. It then seamlessly creates and manages corresponding policies on SRX Firewalls to block malicious IPs.

## Key Features

- **Fetch Malicious IP List**: Fetch the latest list of malicious IP addresses identified by Criminal IP.
- **Generate Security Policies**: Automatically Creates Security Policies for SRX Firewalls based on the list of malicious IPs retrieved by Criminal IP.
- **Update and Manage Policies**: Periodically review, update and remove obsolete IPs to keep the firewall secure and optimized. 

## Prerequisites

Before using this system, ensure you have the following:

- **Criminal IP API Key:** Obtain from Criminal IP after logging in.
- **Juniper SRX/vSRX IP:** The IP address of the Juniper SRX/vSRX device used for connection.
- **Juniper SRX/vSRX Port:** Port used for connecting to the SRX/vSRX management interface
- **Juniper SRX/vSRX API User:** The username used to authenticate with the Juniper SRX/vSRX API
- **Juniper SRX/vSRX API Password:** The password associated with the API user for authentication to the SRX/vSRX API.

## Installation

1. Clone the repository:

`git clone https://github.com/criminalip/JuniperSRX-Maliciousip-Autoblock.git`

2. config.py settings:

| Settings | Description |
| ------ | ------ |
|CRIMINALIP_API_KEY|Insert your Criminal IP API KEY here|
|VSRX_IP|Enter your SRX/vSRX IP address|
|VSRX_PORT|Enter the port number used to connect to the SRX/vSRX device management interface|
|API_USER|Enter the username for Junier vSRX/SRX API |
|API_PASSWORD|The password for the API_USER to authenticate to the SRX/vSRX API|

## Project Structure

📦juniper_srx-maliciousip-autoblock  
 ┣ 📂api  
 ┃ ┣ 📂criminalip  
 ┃ ┃ ┣ 📜__init__.py  
 ┃ ┃ ┣ 📜cip_request_get_ip.py  
 ┃ ┃ ┗ 📜manage_files.py  
 ┃ ┣ 📂juniper_networks  
 ┃ ┃ ┣ 📜__init__.py  
 ┃ ┃ ┣ 📜api.py  
 ┃ ┃ ┗ 📜utils.py  
 ┣ 📜cip_c2_detect_query.json  
 ┣ 📜config.py   
 ┗ 📜main.py

## Usage

`python main.py`


## Example

Shows an example of how uploaded IP addresses can be organized into a single set, and how to manage the particular set by policy

![Image](https://github.com/user-attachments/assets/4d09903e-8449-41a8-802a-5f94529ca733)

![Image](https://github.com/user-attachments/assets/efe48012-6032-48ad-86fd-cc3e896bfd4b)