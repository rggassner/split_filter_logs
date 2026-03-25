#!/usr/bin/env python3
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOURKEYHERE&suffix=tar.gz" -O GeoLite2-City.tar.gz
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=ROURKEYHERE&suffix=tar.gz" -O GeoLite2-ASN.tar.gz

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

def clean_path(text):
    """Removes or replaces characters that are unsafe for directory names."""
    if not text:
        return UNKNOWN_FOLDER
    # Replace slashes, backslashes, and other tricky chars with underscores
    return re.sub(r'[\\/*?:"<>|]', "_", str(text)).strip()

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_target_path(city_reader, asn_reader, ip, info_level):
    """Returns a list of folder names based on the requested information level."""
    try:
        # 1. Handle AS-based Logic
        if info_level in ["as_number_name", "as_network"]:
            asn_res = asn_reader.asn(ip)
            as_num = f"AS{asn_res.autonomous_system_number}"
            as_name = clean_path(asn_res.autonomous_system_organization)
            as_folder = f"{as_num}_{as_name}"

            if info_level == "as_number_name":
                return [as_folder]

            # as_network includes the mask, using underscore for filesystem safety
            network_info = clean_path(str(asn_res.network).replace("/", "_"))
            return [as_folder, network_info]

        # 2. Handle Geo-based Logic (Nested)
        city_res = city_reader.city(ip)
        country = clean_path(city_res.country.name)

        if info_level == "country":
            return [country]

        region = clean_path(city_res.subdivisions.most_specific.name)
        if info_level == "region":
            return [country, region]

        city = clean_path(city_res.city.name)
        return [country, region, city]

    except Exception:
        return [UNKNOWN_FOLDER]

def process_files(input_dir, output_dir, city_db, asn_db, action, info_level):
    if not all(os.path.exists(p) for p in [city_db, asn_db]):
        print("Error: Both City and ASN databases are required.")
        return

    os.makedirs(output_dir, exist_ok=True)
    c_reader = geoip2.database.Reader(city_db)
    a_reader = geoip2.database.Reader(asn_db)

    count = 0
    abs_output = os.path.abspath(output_dir)

    for filename in os.listdir(input_dir):
        full_path = os.path.join(input_dir, filename)
        if not os.path.isfile(full_path) or os.path.abspath(full_path).startswith(abs_output):
            continue

        match = IP_REGEX.search(filename)
        if not match: continue

        ip = match.group(1)

        if is_private_ip(ip):
            sub_dirs = [PRIVATE_FOLDER]
        else:
            sub_dirs = get_target_path(c_reader, a_reader, ip, info_level)

        target_path = os.path.join(output_dir, *sub_dirs)
        os.makedirs(target_path, exist_ok=True)
        dest_file = os.path.join(target_path, filename)

        if action == "move":
            shutil.move(full_path, dest_file)
        else:
            shutil.copy2(full_path, dest_file)

        print(f"[{action.upper()}] {filename} -> {'/'.join(sub_dirs)}/")
        count += 1

    c_reader.close()
    a_reader.close()
    print(f"\nProcessing complete. {count} files handled.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sort logs by GeoIP or ASN hierarchy.")
    parser.add_argument("input_dir", help="Source directory")
    parser.add_argument("city_db", help="Path to GeoLite2-City.mmdb")
    parser.add_argument("asn_db", help="Path to GeoLite2-ASN.mmdb")
    parser.add_argument("--output-directory", required=True, help="Target directory")
    parser.add_argument("--action", choices=["copy", "move"], default="copy")
    parser.add_argument("--information",
                        choices=["country", "region", "city", "as_number_name", "as_network"],
                        default="country")

    args = parser.parse_args()
    process_files(args.input_dir, args.output_directory, args.city_db, args.asn_db, args.action, args.information)


