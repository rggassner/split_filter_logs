#!/usr/bin/env python3
import os
import re
import gzip
import ipaddress
from multiprocessing import Pool, cpu_count
import argparse

# Example config
SPLITTERS = [
    {
        "name": "split_by_user",
        "split_function": r'user="(?:.*?\()?(?P<username>[a-zA-Z0-9._-]+)\s*(?:\))?"',
        "filter": [""],  # match all users if filter is [""] or empty
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
    },
    {
        "name": "split_by_src",
        "split_function": r'src="(?P<src>.*?)"',
        "filter": [],  # ignored if filter_from_file is set
        "filter_from_file": "src.filter",  # <-- one IP/network per line
        "enabled": True,
        "type": "ip"
    },
    {
        "name": "split_by_dst",
        "split_function": r'dst="(?P<dst>.*?)"',
        "filter": [],
        "filter_from_file": "dst.filter",
        "enabled": True,
        "type": "ip"
    },
    {
        "name": "split_by_client_name",
        "split_function": r'client_name="(?P<clientname>.*?)"',
        "filter": [""],
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
    }
]

def load_filter_list(splitter):
    """Load filters from file and/or inline list."""
    filters = list(splitter.get("filter", []))  # start with inline filter
    if splitter.get("filter_from_file"):
        try:
            with open(splitter["filter_from_file"], "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    filters.append(line)
        except Exception as e:
            print(f"Warning: could not load filter file {splitter['filter_from_file']} for {splitter['name']}: {e}")
    return filters


# Precompile regexes and capture group names for enabled rules
COMPILED_SPLITTERS = []
for splitter in SPLITTERS:
    if not splitter.get("enabled", True):
        continue
    pattern = re.compile(splitter["split_function"])
    match = re.search(r'\?P<(\w+)>', splitter["split_function"])
    group = match.group(1) if match else None

    # Get filter list (inline or from file)
    raw_filters = load_filter_list(splitter)

    # Prepare filter by type
    ftype = splitter.get("type", "string")
    if ftype == "ip":
        ip_filters = []
        for f in raw_filters:
            if not f or f.strip() == "":
                ip_filters.append("")  # match all
                continue
            try:
                if "/" in f:
                    ip_filters.append(ipaddress.ip_network(f, strict=False))
                else:
                    ip_filters.append(ipaddress.ip_address(f))
            except ValueError:
                print(f"Warning: invalid IP/network in filter for {splitter['name']}: {f}")
        filter_set = ip_filters
    else:
        filter_set = set(raw_filters)

    COMPILED_SPLITTERS.append({
        "name": splitter["name"],
        "regex": pattern,
        "filter": filter_set,
        "group": group,
        "type": ftype
    })

def open_maybe_gz(file_path):
    if file_path.endswith(".gz"):
        return gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
    else:
        return open(file_path, 'r', encoding='utf-8', errors='ignore')

def make_dirs(path):
    if not os.path.exists(path):
        os.makedirs(path)

def match_filter(value, splitter):
    """Check if value matches filter depending on type"""
    filters = splitter["filter"]
    if not filters or "" in filters:
        return True  # match all

    if splitter["type"] == "ip":
        try:
            ip_val = ipaddress.ip_address(value)
        except ValueError:
            return False
        for f in filters:
            if isinstance(f, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                if ip_val == f:
                    return True
            elif isinstance(f, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if ip_val in f:
                    return True
        return False
    else:
        return value in filters

def process_file(args):
    file_path, output_dir = args
    try:
        with open_maybe_gz(file_path) as infile:
            for line in infile:
                for splitter in COMPILED_SPLITTERS:
                    match = splitter["regex"].search(line)
                    if match:
                        value = match.group(splitter["group"]) if splitter["group"] else match.group(0)
                        if match_filter(value, splitter):
                            out_dir = os.path.join(output_dir, splitter["name"])
                            make_dirs(out_dir)
                            out_path = os.path.join(out_dir, value + ".log")
                            with open(out_path, 'a') as f:
                                f.write(line)
        print("Processed:", file_path)
    except Exception as e:
        print("Error processing {}: {}".format(file_path, e))

def collect_files(input_dir):
    file_list = []
    for root, _, files in os.walk(input_dir):
        for name in files:
            file_list.append(os.path.join(root, name))
    return sorted(file_list)

def main(input_dir, output_dir, processes):
    make_dirs(output_dir)
    files = collect_files(input_dir)
    tasks = [(f, output_dir) for f in files]

    print("Discovered {} files. Starting pool with {} processes...".format(len(files), processes))
    pool = Pool(processes)
    pool.map(process_file, tasks)
    pool.close()
    pool.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Directory with input log files (.gz or plain text)")
    parser.add_argument("output_dir", help="Directory to store filtered logs")
    parser.add_argument("--processes", type=int, default=cpu_count(),
                        help="Number of worker processes (default: all CPUs)")
    args = parser.parse_args()

    main(args.input_dir, args.output_dir, args.processes)
