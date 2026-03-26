#!venv/bin/python3
#pylint: disable=too-many-locals, too-many-arguments, broad-exception-caught, too-many-positional-arguments
"""
Log Sorter by Geolocation and ASN

This script automates the organization of log files by identifying IPv4 addresses
within filenames and sorting them into a structured directory hierarchy based on
MaxMind GeoLite2 database information.

Capabilities:
    - Geographic Sorting: Country > Region > City nesting.
    - Network Sorting: Autonomous System (AS) Number-Name > Network Mask nesting.
    - Safety Filtering: Automatically identifies and isolates private/RFC1918 IPs.
    - Filesystem Safety: Sanitizes all folder names to be cross-platform compatible.
    - Flexible Operations: Supports both 'copy' (default) and 'move' actions.

Requirements:
    - geoip2 (Python library)
    - GeoLite2-City.mmdb (From MaxMind)
    - GeoLite2-ASN.mmdb (From MaxMind)

Usage:
    python3 sort_logs_geo_asn.py <input_dir> <city_db> <asn_db>\
        --output-directory <out_dir> [options]

Example:
    python3 sort_logs_geo_asn.py ./logs ./city.mmdb ./asn.mmdb \
        --output-directory ./sorted --information as_network --action move
"""
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOURKEYHERE&suffix=tar.gz" -O GeoLite2-City.tar.gz
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=ROURKEYHERE&suffix=tar.gz" -O GeoLite2-ASN.tar.gz
#pip3 install geoip2
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
    """
    Sanitizes a string to make it safe for use as a directory or file name.

    This function removes or replaces characters that are reserved or illegal
    on various filesystems (e.g., Windows, macOS, Linux). It specifically targets
    characters that could interfere with path delimiters or shell commands.

    Args:
        text (str | None): The raw string (such as a Country or AS name)
            to be sanitized.

    Returns:
        str: A sanitized version of the input string with illegal characters
            replaced by underscores ('_'). Returns the global UNKNOWN_FOLDER
            constant if the input is empty or None.

    Note:
        - Replaced characters include: backslashes, forward slashes (/),
          asterisks (*), question marks (?), colons (:), quotes ("),
          less than (<), greater than (>), and pipes (|).
        - Leading and trailing whitespace is stripped to prevent issues
          with directory navigation in terminal environments.
    """
    if not text:
        return UNKNOWN_FOLDER
    # Replace slashes, backslashes, and other tricky chars with underscores
    return re.sub(r'[\\/*?:"<>|]', "_", str(text)).strip()

def is_private_ip(ip):
    """
    Checks if a given IP address belongs to a private, local, or reserved range.

    This function validates the IP format and determines if it resides within
    private network blocks (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    as defined by RFC 1918, or other reserved ranges.

    Args:
        ip (str): The IP address string extracted from the filename.

    Returns:
        bool: True if the address is private, local, or loopback.
            Returns False if the address is public or if the string is
            not a valid IP address.

    Note:
        - This acts as a safety filter to prevent the script from querying
          external databases for internal infrastructure IPs.
        - Invalid IP strings (e.g., "999.999.999.999") are caught by the
          ValueError exception and treated as False.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_target_path(city_reader, asn_reader, ip, info_level):
    """
    Determines the directory hierarchy for an IP address based on the requested detail level.

    This function queries both GeoLite2-City and GeoLite2-ASN databases to construct 
    a list of folder names. It supports two primary branches: Geographic (Country -> 
    Region -> City) and Network (AS Number-Name -> Network Mask).

    Args:
        city_reader (geoip2.database.Reader): An open MaxMind City database reader.
        asn_reader (geoip2.database.Reader): An open MaxMind ASN database reader.
        ip (str): The IP address string extracted from the filename.
        info_level (str): The specific level of detail to return. 
            Valid options: 'country', 'region', 'city', 'as_number_name', 'as_network'.

    Returns:
        list[str]: A list of sanitized directory names representing the relative path.
            Example: ['United_States', 'California', 'Mountain_View']
            Returns [UNKNOWN_FOLDER] if the lookup fails or data is missing.

    Raises:
        None: Internal exceptions are caught and return a default 'UNKNOWN' path.
        
    Note:
        - All folder names are passed through `clean_path` to ensure filesystem safety.
        - Forward slashes in network masks (e.g., /24) are replaced with underscores.
    """
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
    """
    Orchestrates the sorting of files based on IP addresses found in their filenames.

    This function iterates through the input directory, identifies IP addresses using 
    regex, queries GeoLite2 databases for location or ASN data, and organizes 
    files into a structured directory hierarchy.

    Args:
        input_dir (str): Path to the directory containing files to be processed.
        output_dir (str): Path where the organized directory structure will be created.
        city_db (str): Path to the MaxMind GeoLite2-City (.mmdb) database.
        asn_db (str): Path to the MaxMind GeoLite2-ASN (.mmdb) database.
        action (str): The file operation to perform; either 'copy' or 'move'.
        info_level (str): Determines the depth and type of the folder structure. 
            Options: 'country', 'region', 'city', 'as_number_name', 'as_network'.

    Returns:
        None: Prints progress to stdout and handles file operations directly.

    Note:
        - Files without an identifiable IP address are skipped.
        - Private IP addresses are automatically routed to a 'PRIVATE' folder.
        - Directory names are sanitized to ensure filesystem compatibility.
        - To avoid infinite loops, files already located within the output 
          directory path are ignored.
    """
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
        if not match:
            continue

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
    process_files(
            args.input_dir,
            args.output_directory,
            args.city_db,
            args.asn_db,
            args.action,
            args.information
        )


