import csv
import json
import logging
import os
from datetime import datetime
from config import OUTPUT_FILE_PATH, SEVEN_DAYS_AGO, yesterday_date, PREVIOUS_CSV_FILE_PATH, TODAY_CSV_FILE_PATH, CSV_FILE_PATH

class QueryData:
    def __init__(self, data):
        self.data = data

    @classmethod
    def from_file(cls, query_file_name):
        with open(query_file_name, "r") as query_file:
            data = json.load(query_file)
            for key, value in data["data"].items():
                data["data"][key] = [
                    item.replace("{% now_date %}", yesterday_date) for item in value
                ]
        return cls(data["data"])


def merge_and_update_ip_addresses():
    """Read CSVs of Malicious IPs and Updates Them"""
    if not os.path.exists(PREVIOUS_CSV_FILE_PATH) and not os.path.exists(TODAY_CSV_FILE_PATH):
        os.makedirs(os.path.dirname(TODAY_CSV_FILE_PATH), exist_ok=True)
        rows_to_write = [['Date', 'IP Address']]
        new_ip_addresses = set()
        
        if os.path.exists(CSV_FILE_PATH):
            try:
                with open(CSV_FILE_PATH, 'r', newline='') as file:
                    reader = csv.reader(file)
                    headers = next(reader, None)
                    
                    for row in reader:
                        if len(row) >= 2:
                            rows_to_write.append([row[0], row[1]])
                            new_ip_addresses.add(row[1])
                
                logging.info(f"Read {len(rows_to_write)-1} entries from {CSV_FILE_PATH}")
            except Exception as e:
                logging.error(f"Error reading {CSV_FILE_PATH}: {str(e)}")
        else:
            logging.warning(f"Both {PREVIOUS_CSV_FILE_PATH} and {CSV_FILE_PATH} don't exist.")
        
        with open(TODAY_CSV_FILE_PATH, 'w', newline='') as today_file:
            writer = csv.writer(today_file)
            writer.writerows(rows_to_write)
        
        logging.info(f"Created {TODAY_CSV_FILE_PATH} with {len(rows_to_write)-1} entries")
        
        return new_ip_addresses, None
    elif not os.path.exists(PREVIOUS_CSV_FILE_PATH) and os.path.exists(TODAY_CSV_FILE_PATH):
        rows_to_copy = []
        with open(TODAY_CSV_FILE_PATH, 'r', newline='') as today_file:
            reader = csv.reader(today_file)
            headers = next(reader, None)
            rows_to_copy.append(['Date', 'IP Address'])
            
            for row in reader:
                if len(row) >= 2:
                    rows_to_copy.append([row[0], row[1]])
        
        # Write to previous file
        with open(PREVIOUS_CSV_FILE_PATH, 'w', newline='') as prev_file:
            writer = csv.writer(prev_file)
            writer.writerows(rows_to_copy)
        
        # Now filter out data older than 7 days from today's file
        filtered_rows = [['Date', 'IP Address']]
        filtered_ips = set()
        delete_ips = set()
        
        with open(TODAY_CSV_FILE_PATH, 'r', newline='') as today_file:
            reader = csv.reader(today_file)
            headers = next(reader, None)
            
            for row in reader:
                if len(row) >= 2:
                    date_str = row[0]
                    ip = row[1]
                    
                    try:
                        entry_date = datetime.strptime(date_str, "%Y-%m-%d")
                        if entry_date >= SEVEN_DAYS_AGO:
                            filtered_rows.append([date_str, ip])
                            filtered_ips.add(ip)
                        else:
                            delete_ips.add(ip)
                    except ValueError:
                        logging.warning(f"Invalid date format in row: {row}")
        
        logging.info(f"Filtered data to {len(filtered_rows)-1} entries (removing entries older than 7 days)")
        new_ip_addresses = set()
        if os.path.exists(CSV_FILE_PATH):
            with open(CSV_FILE_PATH, 'r', newline='') as csv_file:
                reader = csv.reader(csv_file)
                headers = next(reader, None)
                today_date = datetime.now().strftime("%Y-%m-%d")
                
                for row in reader:
                    if len(row) >= 2:
                        ip = row[1]
                        if ip not in filtered_ips:  # Check against filtered IPs
                            new_ip_addresses.add(ip)
                            filtered_rows.append([today_date, ip])
        
            logging.info(f"Found {len(new_ip_addresses)} new unique IP addresses from {CSV_FILE_PATH}")
        
        # Write the combined filtered data and new data back to today's file
        with open(TODAY_CSV_FILE_PATH, 'w', newline='') as today_file:
            writer = csv.writer(today_file)
            writer.writerows(filtered_rows)
        
        logging.info(f"Updated {TODAY_CSV_FILE_PATH} with {len(filtered_rows)-1} entries")

        return new_ip_addresses, delete_ips
    elif os.path.exists(PREVIOUS_CSV_FILE_PATH) and os.path.exists(TODAY_CSV_FILE_PATH):
        rows_to_copy = []
        with open(TODAY_CSV_FILE_PATH, 'r', newline='') as today_file:
            reader = csv.reader(today_file)
            headers = next(reader, None)
            rows_to_copy.append(['Date', 'IP Address'])
            
            for row in reader:
                if len(row) >= 2:
                    rows_to_copy.append([row[0], row[1]])
        
        # Write to previous file
        with open(PREVIOUS_CSV_FILE_PATH, 'w', newline='') as prev_file:
            writer = csv.writer(prev_file)
            writer.writerows(rows_to_copy)
        
        # Now filter out data older than 7 days from today's file
        filtered_rows = [['Date', 'IP Address']]
        filtered_ips = set()
        delete_ips = set()
        
        with open(TODAY_CSV_FILE_PATH, 'r', newline='') as today_file:
            reader = csv.reader(today_file)
            headers = next(reader, None)
            
            for row in reader:
                if len(row) >= 2:
                    date_str = row[0]
                    ip = row[1]
                    
                    try:
                        entry_date = datetime.strptime(date_str, "%Y-%m-%d")
                        if entry_date >= SEVEN_DAYS_AGO:
                            filtered_rows.append([date_str, ip])
                            filtered_ips.add(ip)
                        else:
                            delete_ips.add(ip)
                    except ValueError:
                        logging.warning(f"Invalid date format in row: {row}")
        
        logging.info(f"Filtered data to {len(filtered_rows)-1} entries (removing entries older than 7 days)")
        
        # Process new data from CSV_FILE_PATH if it exists
        new_ip_addresses = set()
        if os.path.exists(CSV_FILE_PATH):
            with open(CSV_FILE_PATH, 'r', newline='') as csv_file:
                reader = csv.reader(csv_file)
                headers = next(reader, None)
                
                today_date = datetime.now().strftime("%Y-%m-%d")
                
                for row in reader:
                    if len(row) >= 2:
                        ip = row[1]
                        if ip not in filtered_ips:  # Check against filtered IPs
                            new_ip_addresses.add(ip)
                            filtered_rows.append([today_date, ip])
        
            logging.info(f"Found {len(new_ip_addresses)} new unique IP addresses from {CSV_FILE_PATH}")
        
        # Write the combined filtered data and new data back to today's file
        with open(TODAY_CSV_FILE_PATH, 'w', newline='') as today_file:
            writer = csv.writer(today_file)
            writer.writerows(filtered_rows)
        
        logging.info(f"Updated {TODAY_CSV_FILE_PATH} with {len(filtered_rows)-1} entries")

        return new_ip_addresses, delete_ips
 
    
def output_result(new_ip_addresses):
    """Output the final record of today's malicious IPs"""
    if new_ip_addresses and not os.path.exists(OUTPUT_FILE_PATH):
        rows_to_write = [['Date', 'IP Address']]

        today_date = datetime.now().strftime("%Y-%m-%d")

        for ip in new_ip_addresses:
            rows_to_write.append([today_date, ip])

        try:
            with open(OUTPUT_FILE_PATH, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(rows_to_write)
            logging.info(f"Created {OUTPUT_FILE_PATH} with {len(new_ip_addresses)} new entries.")
        except Exception as e:
            logging.error(f"Error writing to {OUTPUT_FILE_PATH}: {str(e)}")
    else:
        logging.info(f"Today's Output File has been already made")




