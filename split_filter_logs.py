#!/usr/bin/env python3
import subprocess
import os
import re
import gzip
import bz2
import lzma
import zipfile
import ipaddress
from multiprocessing import Pool, cpu_count
import argparse

# Example config
SPLITTERS = [
    {
        "name": "split_by_user",
        "split_function": r'user="(?:.*?\()?(?P<username>[a-zA-Z0-9._-]+)\s*(?:\))?"',
        "filter": [], 
        "filter_from_file": "uniqusers",
        "enabled": True,
        "type": "string"
    },
    {
        "name": "split_by_src",
        "split_function": r'src="(?P<src>.*?)"',
        "filter": [""], 
        "filter_from_file": "",  
        "enabled": False,
        "type": "ip"
    },
    {
        "name": "split_by_dst",
        "split_function": r'dst="(?P<dst>.*?)"',
        "filter": [""],
        "filter_from_file": "",
        "enabled": False,
        "type": "ip"
    },
    {
        "name": "split_by_status",
        "split_function": r'status="(?P<status>.*?)"',
        "filter": ["Success"],
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
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
            with open(splitter["filter_from_file"], "r") as f:  # no encoding arg in 3.4
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    filters.append(line)
        except Exception as e:
            print("Warning: could not load filter file {} for {}: {}".format(
                splitter.get("filter_from_file", ""), splitter.get("name", ""), e))
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
                print("Warning: invalid IP/network in filter for {}: {}".format( splitter.get("name", ""), f))
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

def open_maybe_compressed(file_path, strict=False):
    """
    Open file as plain text or decompressed text using magic bytes.
    Supports: plain, gzip, bz2, xz/lzma, zip.
    
    If strict=True: raise ValueError on unknown formats
    If strict=False: print warning and return None
    """
    # Magic headers
    GZIP_MAGIC  = b"\x1f\x8b"
    BZ2_MAGIC   = b"BZh"
    XZ_MAGIC    = b"\xfd7zXZ\x00"
    ZIP_MAGIC   = b"\x50\x4B\x03\x04"   # PK..

    # Read first 6 bytes for detection
    with open(file_path, "rb") as f:
        header = f.read(6)

    # --- GZIP ---
    if header.startswith(GZIP_MAGIC):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="ignore")

    # --- BZ2 ---
    if header.startswith(BZ2_MAGIC):
        return bz2.open(file_path, "rt", encoding="utf-8", errors="ignore")

    # --- XZ/LZMA ---
    if header.startswith(XZ_MAGIC):
        return lzma.open(file_path, "rt", encoding="utf-8", errors="ignore")

    # --- ZIP ---
    if header.startswith(ZIP_MAGIC):
        try:
            z = zipfile.ZipFile(file_path)
            # Return concatenated line iterators from each file inside
            def generator():
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    with z.open(info, "r") as f:
                        for line in f:
                            yield line.decode("utf-8", errors="ignore")
            return generator()
        except Exception as e:
            msg = f"Error reading ZIP file '{file_path}': {e}"
            if strict:
                raise ValueError(msg)
            print("Warning:", msg)
            return None

    # --- Plain text check ---
    if all(32 <= b <= 126 or b in (9, 10, 13) for b in header if b != 0):
        return open(file_path, "r", encoding="utf-8", errors="ignore")

    # --- Unknown format ---
    msg = f"Unsupported file format in '{file_path}', magic bytes={header.hex()}"
    if strict:
        raise ValueError(msg)
    print("Warning:", msg)
    return None

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
        infile = open_maybe_compressed(file_path, strict=False)
        if infile is None:
            print("Skipping unsupported file:", file_path)
            return
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
    # Get number of CPU cores for GNU sort parallel mode
    try:
        nproc = str(os.cpu_count())
    except Exception:
        nproc = "1"

    print("Sorting output files with system 'sort -n --parallel={}'...".format(nproc))
    
    for root, _, files in os.walk(output_dir):
        for name in files:
            if not name.endswith(".log"):
                continue
            path = os.path.join(root, name)
            try:
                subprocess.run(
                    [
                        "sort",
                        "-n",                 # numeric sort by first field
                        "--parallel=" + nproc,
                        "-o", path, path      # in-place external merge sort
                    ],
                    check=True
                )
            except Exception as e:
                print("Warning: could not sort {}: {}".format(path, e))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Directory with input log files (.gz or plain text)")
    parser.add_argument("output_dir", help="Directory to store filtered logs")
    parser.add_argument("--processes", type=int, default=cpu_count(),
                        help="Number of worker processes (default: all CPUs)")
    args = parser.parse_args()

    main(args.input_dir, args.output_dir, args.processes)
