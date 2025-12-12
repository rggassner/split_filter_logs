#!/usr/bin/env python3
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=INSERT_YOUR_LICENSE_KEY_HERE&suffix=tar.gz" -O GeoLite2-Country.tar.gz
import os
import re
import shutil
import ipaddress
import argparse
import geoip2.database

# -------- CONFIG --------
PRIVATE_FOLDER = "PRIVATE"
UNKNOWN_FOLDER = "UNKNOWN"
# ------------------------

IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

def get_country(reader, ip):
    try:
        response = reader.country(ip)
        return response.country.iso_code or UNKNOWN_FOLDER
    except Exception:
        return UNKNOWN_FOLDER

def process_files(base_dir, db_path):
    reader = geoip2.database.Reader(db_path)

    for filename in os.listdir(base_dir):
        match = IP_REGEX.search(filename)
        if not match:
            continue

        ip = match.group(1)
        full_path = os.path.join(base_dir, filename)

        if not os.path.isfile(full_path):
            continue

        # Determine target folder
        if is_private_ip(ip):
            target = PRIVATE_FOLDER
        else:
            country = get_country(reader, ip)
            target = country if country else UNKNOWN_FOLDER

        # Create directory if missing
        target_dir = os.path.join(base_dir, target)
        os.makedirs(target_dir, exist_ok=True)

        # Move file
        shutil.move(full_path, os.path.join(target_dir, filename))
        print(f"[OK] {filename} -> {target}/")

    reader.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sort log files by IP geolocation.")
    parser.add_argument("directory", help="Directory containing .log files")
    parser.add_argument("database", help="Path to GeoLite2-Country.mmdb")

    args = parser.parse_args()
    process_files(args.directory, args.database)
