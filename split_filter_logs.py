#!/usr/bin/env python3
#pylint: disable=broad-exception-caught,too-many-statements,too-many-branches,global-statement,too-many-locals,too-many-positional-arguments,too-many-arguments
import subprocess
import fcntl
import io
import os
import re
import sys
import gzip
import json
import bz2
import lzma
import zipfile
import ipaddress
import argparse
import hashlib
import tarfile
from datetime import datetime, timedelta
from multiprocessing import Pool, cpu_count

SPLITTERS =[]

def load_config():
    conf_path = os.path.join(os.path.dirname(__file__), '', 'splitters.conf')
    try:
        with open(conf_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return []

def get_compiled_splitters(splitter_data, ignore_case):
    compiled_list = []
    # Use flags for regex (IPs aren't case sensitive, but the surrounding text might be)
    flags = re.IGNORECASE if ignore_case else 0

    for splitter in splitter_data:
        if not splitter.get("enabled", True):
            continue

        raw_filters = load_filter_list(splitter)
        ftype = splitter.get("type", "string")
        
        pattern = None
        group = splitter.get("name")
        filter_set = None

        # 1. Compile the Extraction Regex (Required for 'ip' and 'string' types)
        if "split_function" in splitter:
            pattern = re.compile(splitter["split_function"], flags)
            match = re.search(r'\?P<(\w+)>', splitter["split_function"])
            group = match.group(1) if match else None

        # 2. Prepare the Filter Logic
        if ftype == "start_string":
            if not raw_filters: continue
            filter_set = tuple(f.lower() if ignore_case else f for f in raw_filters if f)
        
        elif ftype == "global_string":
            if not raw_filters: continue
            filter_set = {f.lower() if ignore_case else f for f in raw_filters if f}
            
        elif ftype == "ip":
            # Convert raw strings into IP objects for math-based comparison
            filter_set = []
            for fr in raw_filters:
                if not fr: continue
                try:
                    # Logic: if it has a slash, it's a network/CIDR; otherwise, it's a single address
                    filter_set.append(ipaddress.ip_network(fr, strict=False) if "/" in fr else ipaddress.ip_address(fr))
                except ValueError:
                    print(f"Warning: invalid IP filter: {fr}")
        
        else: # Default/String Regex type
            filter_set = {f.lower() if ignore_case else f for f in raw_filters if f}

        compiled_list.append({
            "name": splitter["name"],
            "regex": pattern,
            "filter": filter_set,
            "group": group,
            "type": ftype,
            "ignore_case": ignore_case 
        })
    return compiled_list

def hash_worker(file_path):
    stats = get_file_stats(file_path)
    return file_path, stats

def get_file_stats(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    size = os.path.getsize(file_path)

    with open(file_path, "rb") as fst:
        # Read in 64kb chunks to stay memory-efficient
        for byte_block in iter(lambda: fst.read(65536), b""):
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)

    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "size": size
    }

def reset_metadata(tarinfo):
    tarinfo.uid = tarinfo.gid = 0
    tarinfo.uname = tarinfo.gname = "root"
    tarinfo.mtime = 0
    return tarinfo

def load_filter_list(l_splitter):
    filters = list(l_splitter.get("filter", []))
    if l_splitter.get("filter_from_file"):
        try:
            # Specify utf-8 and surrogateescape for consistency
            with open(l_splitter["filter_from_file"],
                      "r",
                      encoding="utf-8",
                      errors="surrogateescape"
                      ) as splitter_f:
                for line in splitter_f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    filters.append(line)
        except Exception as e:
            print(f"Warning: could not load filter file"
                  f" {splitter.get('filter_from_file', '')} "
                  f" for {splitter.get('name', '')}: {e}")
    return filters


COMPILED_SPLITTERS = []
for splitter in SPLITTERS:
    if not splitter.get("enabled", True):
        continue

    # --- STRICT FILTER FILE CHECK ---
    filter_file = splitter.get("filter_from_file")
    if filter_file:
        if not os.path.exists(filter_file):
            print(f"\n[!] FATAL ERROR: Filter file '{filter_file}' not found!")
            print(f"Required by splitter: {splitter.get('name')}")
            print("Aborting to prevent incomplete processing.")
            sys.exit(1) # Kill the script immediately

    raw_filters = load_filter_list(splitter)
    
    if splitter.get("type") == "global_string":
        if not raw_filters:
            continue
            
        escaped_keywords = [re.escape(f) for f in raw_filters if f]
        combined_regex = rf'.*(?P<{splitter["name"]}>' + "|".join(escaped_keywords) + r').*'
        
        # --- FLAG ADDED HERE ---
        pattern = re.compile(combined_regex, re.IGNORECASE) 
        group = splitter["name"]
    else:
        # --- FLAG ADDED HERE AS WELL ---
        pattern = re.compile(splitter["split_function"], re.IGNORECASE)
        match = re.search(r'\?P<(\w+)>', splitter["split_function"])
        group = match.group(1) if match else None


    # 3. Prepare filter by type
    ftype = splitter.get("type", "string")
    if ftype == "ip":
        ip_filters = []
        for f in raw_filters:
            if not f or f.strip() == "":
                ip_filters.append("") 
                continue
            try:
                ip_filters.append(ipaddress.ip_network(f, strict=False) if "/" in f else ipaddress.ip_address(f))
            except ValueError:
                print(f"Warning: invalid IP filter: {f}")
        filter_set = ip_filters
    else:
        # For global_string, we don't need a separate filter set because 
        # the Regex itself IS the filter.
        # filter_set = set(raw_filters)
        filter_set = {f.lower() for f in raw_filters if f}

    COMPILED_SPLITTERS.append({
        "name": splitter["name"],
        "regex": pattern,
        "filter": filter_set,
        "group": group,
        "type": ftype
    })

def open_maybe_compressed(file_path, strict=False): #pylint: disable=too-many-return-statements
    # Magic headers
    gzip_magic  = b"\x1f\x8b"
    bz2_magic   = b"BZh"
    xz_magic    = b"\xfd7zXZ\x00"
    zip_magic   = b"\x50\x4B\x03\x04"   # PK..

    # Read first 6 bytes for detection
    with open(file_path, "rb") as head_f:
        header = head_f.read(6)

    # --- GZIP ---
    if header.startswith(gzip_magic):
        #return gzip.open(file_path, "rt", encoding="utf-8", errors="ignore")
        return io.TextIOWrapper(
            io.BufferedReader(
                gzip.open(file_path, "rb"),
                buffer_size=16 * 1024 * 1024
            ),
            encoding="utf-8",
            errors="ignore"
        )    

    # --- BZ2 ---
    if header.startswith(bz2_magic):
        #return bz2.open(file_path, "rt", encoding="utf-8", errors="ignore")
        return io.TextIOWrapper(
            io.BufferedReader(
                bz2.open(file_path, "rb"),
                buffer_size=16 * 1024 * 1024
            ),
            encoding="utf-8",
            errors="ignore"
        )    

    # --- XZ/LZMA ---
    if header.startswith(xz_magic):
        #return lzma.open(file_path, "rt", encoding="utf-8", errors="ignore")
        return io.TextIOWrapper(
            io.BufferedReader(
                lzma.open(file_path, "rb"),
                buffer_size=16 * 1024 * 1024
            ),
            encoding="utf-8",
            errors="ignore"
        )    

    # --- ZIP ---
    if header.startswith(zip_magic):
        try:
            # Using 'with' to ensure ZipFile is properly closed after use
            with zipfile.ZipFile(file_path) as z:
                # Return concatenated line iterators from each file inside
                def generator():
                    for info in z.infolist():
                        if info.is_dir():
                            continue
                        with z.open(info, "r") as zip_f:
                            for line in zip_f:
                                yield line.decode("utf-8", errors="ignore")
                return generator()

        except Exception as e: 
            msg = f"Error reading ZIP file '{file_path}': {e}"
            if strict:
                raise ValueError(msg) from e  # Re-raise with original exception context
            print("Warning:", msg)
            return None

    # --- Plain text check ---
    if all(32 <= b <= 126 or b in (9, 10, 13) for b in header if b != 0):
        return io.TextIOWrapper(
            io.BufferedReader(
                open(file_path, "rb"),
                buffer_size=1024 * 1024 * 16 # 1 MB
            ),
            encoding="utf-8",
            errors="ignore"
        )

    # --- Unknown format ---
    msg = f"Unsupported file format in '{file_path}', magic bytes={header.hex()}"
    if strict:
        raise ValueError(msg)
    print("Warning:", msg)
    return None

def make_dirs(path):
    if not os.path.exists(path):
        os.makedirs(path)


def match_filter(value, f_splitter):
    """
    Evaluates whether an extracted value satisfies the filter criteria
    defined in a splitter configuration.

    The filtering behavior depends on the splitter type:
        - "ip": Performs exact IP or CIDR membership checks using `ipaddress`.
        - "global_string": Always returns True (filtering handled at regex level).
        - default/string: Performs membership check against a set of allowed values.

    Parameters
    ----------
    value : str
        Extracted value from a log line (e.g., IP address or keyword).
    f_splitter : dict
        Splitter configuration containing:
            - "type" (str): Type of matching logic ("ip", "global_string", or string).
            - "filter" (iterable): Collection of allowed values or IP/network objects.
            - "ignore_case" (bool, optional): Whether to normalize case for comparison.

    Returns
    -------
    bool
        True if the value matches the filter criteria or if no filters are defined;
        False otherwise.

    Behavior
    --------
    - If no filters are configured, all values are accepted.
    - IP filters support both exact matches and CIDR range inclusion.
    - Invalid IP values are safely rejected.
    - String filters optionally normalize case before comparison.

    Notes
    -----
    - Designed to be lightweight, as it is called for every matched log line.
    - Assumes IP filters are precompiled into `ipaddress` objects.
    """
    filters = f_splitter["filter"]
    # If no filters defined, everything passes
    if not filters:
        return True

    if f_splitter["type"] == "ip":
        try:
            # Convert the string found in the log line to an IP object
            ip_val = ipaddress.ip_address(value.strip())
            for fi in filters:
                # Check if it's an exact match OR if the IP is inside the network (CIDR)
                if (isinstance(fi, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and ip_val == fi) or \
                   (isinstance(fi, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and ip_val in fi):
                    return True
        except ValueError: 
            return False # Capturing group wasn't a valid IP
        return False
    
    if f_splitter["type"] == "global_string":
        return True # Handled by the regex in process_line

    # Standard string matching
    match_val = value.lower() if f_splitter.get("ignore_case") else value
    return match_val in filters


def process_file_with_size(file_args):
    """
    Wrapper around `process_file` that also returns the input file size.

    This helper is designed for use in parallel processing workflows where
    both file processing and progress tracking (based on bytes processed)
    are required. It retrieves the file size upfront, delegates the actual
    processing to `process_file`, and returns metadata for aggregation.

    Parameters
    ----------
    file_args : tuple
        Tuple containing:
            - file_path (str): Path to the input file.
            - output_dir (str): Base directory for processed output.

    Returns
    -------
    tuple
        (file_path, file_size) where:
            - file_path (str): Path of the processed file.
            - file_size (int): Size of the file in bytes.

    Behavior
    --------
    - Computes file size before processing begins.
    - Delegates all processing logic to `process_file`.
    - Enables progress estimation based on total bytes processed.

    Notes
    -----
    - Intended for use with multiprocessing (e.g., `Pool.imap_unordered`).
    - File size is retrieved even if processing fails or produces no output.
    """
    file_path, _ = file_args
    file_size = os.path.getsize(file_path)
    process_file(file_args)
    return file_path, file_size

def process_file(file_args):
    """
    Processes a single input file by streaming its contents, applying line-level
    splitting logic, and buffering results for batched disk writes.

    The function opens the file (handling compression transparently), iterates
    over each line, and delegates matching and routing logic to `process_line`.
    Matched lines are accumulated in an in-memory buffer and periodically flushed
    to disk to reduce I/O overhead.

    Parameters
    ----------
    file_args : tuple
        Tuple containing:
            - file_path (str): Path to the input file to process.
            - output_dir (str): Base directory where processed output files will be written.

    Behavior
    --------
    - Supports plain text and multiple compressed formats via `open_maybe_compressed`.
    - Processes files in a streaming fashion to remain memory-efficient.
    - Buffers output lines and flushes them in batches (`buffer_limit`) to optimize disk I/O.
    - Ensures any remaining buffered data is written after processing completes.
    - Logs progress and errors to stdout.

    Error Handling
    --------------
    - Gracefully handles missing files (`FileNotFoundError`).
    - Catches and reports unexpected exceptions without interrupting the overall pipeline.

    Notes
    -----
    - Intended to be executed in parallel (e.g., via multiprocessing Pool).
    - Relies on `process_line` for classification and `flush_buffer` for safe writes.
    - Buffer size is fixed and tuned for performance; adjust `buffer_limit` if needed.
    """
    file_path, output_dir = file_args
    buffer = {}
    buffer_limit = 10000
    current_buffer_size = 0  # <--- Optimization: Persistent counter

    try:
        # Optimization: open_maybe_compressed already handles the stream
        infile = open_maybe_compressed(file_path, strict=False)
        if infile is None:
            return

        for line in infile:
            process_line(line, output_dir, buffer)
            current_buffer_size += 1 # <--- Incremental count

            if current_buffer_size >= buffer_limit:
                flush_buffer(buffer)
                buffer.clear()
                current_buffer_size = 0 # <--- Reset counter

        # Final flush for remaining lines
        if buffer:
            flush_buffer(buffer)

        print(f"Processed: {file_path}")

    except FileNotFoundError as e:
        print(f"File not found: {file_path}. Error: {e}")
    except Exception as e: 
        print(f"Unexpected error processing {file_path}: {e}")

def process_line(line, output_dir, buffer):
    """
    Processes a single log line against all configured splitters and routes it
    to the appropriate output buffer(s).

    For each splitter definition in `COMPILED_SPLITTERS`, this function attempts
    to extract a matching value using one of several strategies:
        - "start_string": checks if the line begins with any configured prefix.
        - "global_string": searches for keyword presence anywhere in the line.
        - "regex"/default: applies a compiled regular expression and extracts
          a named or full match group.

    If a match is found and passes optional filter validation, the line is
    assigned to an output file derived from the splitter name and extracted value.
    Instead of writing immediately to disk, lines are accumulated in `buffer`
    for batch flushing.

    Parameters
    ----------
    line : str
        The input log line to evaluate.
    output_dir : str
        Base directory where categorized log files will be written.
    buffer : dict
        In-memory buffer mapping output file paths (str) to lists of log lines
        (list of str). This function appends matching lines to this structure.

    Behavior
    --------
    - Supports case-sensitive and case-insensitive matching per splitter.
    - Applies optional filtering (e.g., IP matching, keyword filtering).
    - Generates safe output filenames by normalizing or sanitizing extracted values.
    - Allows a single line to match multiple splitters and be written to multiple outputs.

    Notes
    -----
    - Actual file I/O is deferred; `flush_buffer` is responsible for writing to disk.
    - Relies on global `COMPILED_SPLITTERS` configuration.
    - Designed for high-throughput log processing with minimal per-line overhead.
    """
    line_lower = line.lower()
    
    for splitter_line in COMPILED_SPLITTERS:
        value = None
        sp_ftype = splitter_line["type"]
        ignore_case = splitter_line["ignore_case"]
        
        if sp_ftype == "start_string":
            target = line_lower if ignore_case else line
            # This will now succeed because filter is a TUPLE
            if target.startswith(splitter_line["filter"]):
                for kw in splitter_line["filter"]:
                    if target.startswith(kw):
                        value = kw
                        break
        
        elif sp_ftype == "global_string":
            target = line_lower if ignore_case else line
            for kw in splitter_line["filter"]:
                if kw in target:
                    value = kw
                    break
        
        elif splitter_line["regex"]: # Only run if a regex was compiled
            match_line = splitter_line["regex"].search(line)
            if match_line:
                value = match_line.group(splitter_line["group"]) if splitter_line["group"] else match_line.group(0)
                if not match_filter(value, splitter_line):
                    value = None

        # If no match was found by any logic, skip to next splitter
        if value is None:
            continue

        # --- File Writing Logic ---
        if ignore_case:
            target_filename = value.lower()
        else:
            # Sanitize filename
            target_filename = re.sub(r'[?=\s]+', '_', value).strip('_')

        out_dir = os.path.join(output_dir, splitter_line["name"])
        out_path = os.path.join(out_dir, f"{target_filename}.log")
        
        if out_path not in buffer:
            buffer[out_path] = []
        buffer[out_path].append(line)

def flush_buffer(buffer):
    """
    Flushes buffered log lines to their respective output files.

    Iterates over a dictionary mapping output file paths to lists of log lines,
    ensuring that each target directory exists before appending the buffered
    content to disk. File writes are protected with an exclusive lock to
    prevent race conditions when multiple processes write to the same file.

    Parameters
    ----------
    buffer : dict
        Dictionary where keys are output file paths (str) and values are lists
        of log lines (list of str) to be written.

    Behavior
    --------
    - Creates parent directories as needed.
    - Appends all buffered lines to their corresponding files.
    - Uses `fcntl.flock` to guarantee safe concurrent writes.
    - Preserves byte integrity using UTF-8 encoding with `surrogateescape`.

    Notes
    -----
    - Designed for use in multiprocessing environments.
    - Buffer is not cleared by this function; caller is responsible for cleanup.
    """
    for out_path, lines in buffer.items():
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        # Specify encoding and surrogateescape to preserve byte integrity
        with open(out_path, 'a', encoding="utf-8", errors="surrogateescape") as f_buffer:
            fcntl.flock(f_buffer, fcntl.LOCK_EX)
            try:
                f_buffer.write("".join(lines))
            finally:
                fcntl.flock(f_buffer, fcntl.LOCK_UN)

def collect_files(input_dir):
    """
    Recursively collects all file paths from a given directory.

    Walks through the directory tree starting at `input_dir` and gathers
    the full path of every file encountered. The resulting list is sorted
    to ensure deterministic processing order.

    Parameters
    ----------
    input_dir : str
        Root directory to search for files.

    Returns
    -------
    list of str
        Sorted list of absolute file paths found within the directory tree.

    Notes
    -----
    - Traversal includes all subdirectories.
    - Symbolic links are handled according to `os.walk` default behavior.
    """
    file_list = []
    for root, _, files in os.walk(input_dir):
        for name in files:
            file_list.append(os.path.join(root, name))
    return sorted(file_list)


def main(input_dir, output_dir, processes, ignore_case, no_sort, conf_file, no_hash, no_compress, tmp_dir, sort_mem, argsi):
    """
    Orchestrates the full forensic log processing pipeline: configuration loading,
    parallel hashing, log extraction and filtering, optional sorting, and final archiving.

    This function acts as the central coordinator for a multi-phase workflow:
        1. Loads and prepares splitter configuration (with optional CLI overrides).
        2. Compiles splitter rules for log parsing and filtering.
        3. Performs parallel hashing of input files (optional).
        4. Processes files in parallel, extracting and distributing log lines
           into categorized output files based on configured splitters.
        5. Optionally sorts output logs chronologically using system `sort`.
        6. Optionally compresses the final output into a `.tar.xz` archive.
        7. Generates a digest file containing metadata, hashes, and execution summary.

    Parameters
    ----------
    input_dir : str
        Path to the directory containing input log files (supports recursive traversal).
    output_dir : str
        Path where processed and split log files will be written.
    processes : int
        Number of worker processes to use for parallel operations.
    ignore_case : bool
        Whether to perform case-insensitive matching in splitters.
    no_sort : bool
        If True, skips chronological sorting of output log files.
    conf_file : str
        Path to the JSON configuration file defining splitter rules.
    no_hash : bool
        If True, skips hashing of input and output files.
    no_compress : bool
        If True, skips creation of the compressed `.tar.xz` archive.
    tmp_dir : str or None
        Optional temporary directory for external sorting operations.
    sort_mem : str
        Memory limit passed to the `sort` command (e.g., "80%", "4G").
    argsi : argparse.Namespace
        Parsed CLI arguments, used to dynamically enable/disable splitters
        in "Simple Mode".

    Behavior
    --------
    - Supports both "Expert Mode" (config-driven) and "Simple Mode" (CLI-driven module selection).
    - Ensures deterministic processing via hashing and optional sorting.
    - Handles large datasets efficiently using multiprocessing and buffered I/O.
    - Produces a detailed digest file summarizing inputs, outputs, and execution metrics.

    Raises
    ------
    SystemExit
        If configuration loading fails or no valid splitters are enabled.

    Notes
    -----
    - Designed for forensic-scale log processing where traceability and integrity matter.
    - External dependencies include system utilities such as `sort` and `xz`.
    - Output structure is organized per splitter, with one file per matched value.

    """    
    # 1. Load the Configuration
    try:
        with open(conf_file, "r", encoding="utf-8") as fi:
            splitter_data = json.load(fi)
    except Exception as e:
        print(f"[!] FATAL: Could not load config file {conf_file}: {e}")
        sys.exit(1)

    # Modular Logic: Update splitter_data based on CLI flags
    script_diri = os.path.dirname(os.path.abspath(__file__))
    active_via_cli = []

    for itemi in splitter_data:
        # Check for the specific flag name we generated in argparse
        flag_name = f"split_by_{itemi['name']}"

        if getattr(argsi, flag_name, False):
            itemi["enabled"] = True
            active_via_cli.append(itemi['name'])

            # Auto-link the filter file logic
            # Note: I added .txt extension here to match our previous plan
            filter_path = os.path.join(script_diri, "splitters", f"{itemi['name']}.txt")
            if os.path.exists(filter_path):
                itemi["filter_from_file"] = filter_path
        else:
            # If Simple flags are present in the command line at all,
            # we disable anything not explicitly mentioned.
            # We check if ANY split_by flag was passed to the script.
            any_simple_flag_set = any(getattr(argsi, f"split_by_{i['name']}", False) for i in splitter_data)
            if any_simple_flag_set:
                itemi["enabled"] = False

    if active_via_cli:
        print(f"[*] Simple Mode: Activating modules: {', '.join(active_via_cli)}")
    else:
        print("[*] Expert Mode: Using default enabled states from JSON.")

    global COMPILED_SPLITTERS
    COMPILED_SPLITTERS = get_compiled_splitters(splitter_data, ignore_case)

    if not COMPILED_SPLITTERS:
        # Debug helper: print the status of the first item to see why it failed
        if splitter_data:
            print(f"[DEBUG] First splitter state: name={splitter_data[0]['name']}, enabled={splitter_data[0]['enabled']}")
        print("[!] No enabled splitters found in config. Aborting.")
        sys.exit(1)
    start_time = datetime.now()
    digest_lines = [f"Processing Start Time: {start_time}\n", "--- INPUT FILES ---\n"]
    make_dirs(output_dir)
    files = collect_files(input_dir)
    num_files = len(files)
    # --- Phase 1: Parallel Hashing ---
    total_bytes = 0
    num_files = len(files)
    if no_hash:
        print("[!] --no-hash detected. Skipping input file integrity checks.")
        total_bytes = sum(os.path.getsize(f) for f in files)
        digest_lines.append("--- INPUT FILES (HASHING SKIPPED) ---\n")
    else:
        print(f"Phase 1/2: Hashing {num_files} input files on {processes} cores...")
        hash_start = datetime.now()
        total_bytes = 0
        hashed_count = 0
        # We use a Pool context manager for Phase 1
        with Pool(processes) as pool:
            for fi, stats in pool.imap_unordered(hash_worker, files):
                hashed_count += 1
                total_bytes += stats['size']
                # Record in digest
                digest_lines.append(f"{fi} | Size: {stats['size']} |"
                                    f" MD5: {stats['md5']} | SHA256: {stats['sha256']}\n")
                # Calculate Hashing ETA
                elapsed = (datetime.now() - hash_start).total_seconds()
                percent = (hashed_count / num_files) * 100
                if elapsed > 1:
                    files_per_sec = hashed_count / elapsed
                    remaining_files = num_files - hashed_count
                    eta_sec = remaining_files / files_per_sec
                    eta_str = str(timedelta(seconds=int(eta_sec)))
                    print(f"[HASHING: {percent:6.2f}%] Files: {hashed_count}/{num_files} |"
                          f"ETA: {eta_str}      ", end='\r')
    
        print(f"\nHashing complete. Total Data: {total_bytes / (1024**3):.2f} GB\n")

    # --- Phase 2: Parallel Extraction & Filtering ---
    processed_bytes = 0
    processing_start = datetime.now()
    tasks = [(f, output_dir) for f in files]
    print("Phase 2/2: Starting extraction and filtering...")
    with Pool(processes) as pool:
        for file_path, file_size in pool.imap_unordered(process_file_with_size, tasks):
            processed_bytes += file_size
            # Calculate Extraction ETA
            elapsed = (datetime.now() - processing_start).total_seconds()
            percent = (processed_bytes / total_bytes) * 100 if total_bytes > 0 else 100
            if elapsed > 1 and processed_bytes > 0:
                bytes_per_sec = processed_bytes / elapsed
                remaining_bytes = total_bytes - processed_bytes
                eta_seconds = remaining_bytes / bytes_per_sec
                eta_str = str(timedelta(seconds=int(eta_seconds)))
                raw_name = os.path.basename(file_path)
                fname = os.path.basename(file_path)[-40:] if len(raw_name) > 40 else raw_name
                print(f"[FILTERING: {percent:6.2f}%] {fname:<40} | ETA: {eta_str:<20}", end='\r')
    print("\nExtraction phase complete.\n")

    # --- Phase 3: Optimized Sorting ---
    log_files = []
    for root, _, walk_files in os.walk(output_dir):
        for name in walk_files:
            if name.endswith(".log"):
                log_files.append(os.path.join(root, name))
    if no_sort:
        print("\n[!] --no-sort passed. Skipping chronological sorting phase.")
        digest_lines.append("\n--- OUTPUT FILES (UNSORTED) ---\n")
    else:
        print(f"\nPhase 3/3: Sorting {len(log_files)} output files...")
        digest_lines.append("\n--- OUTPUT FILES (SORTED) ---\n")
    digest_lines.append("\n--- OUTPUT FILES ---\n")

    for i, path in enumerate(sorted(log_files), 1):
        try:
            if not no_sort:
                # 1. Detect format (ISO 2026-03-21 vs Syslog Mar 6)
                with open(path, 'r', encoding="utf-8", errors="ignore") as f_check:
                    first_line = f_check.readline()

                # Default ISO-8601 sort
                sort_cmd = ["sort", "--parallel=" + str(processes), "-S", sort_mem, "-o", path, path]

                # Add Tmp Dir if provided
                if tmp_dir:
                    sort_cmd.extend(["-T", tmp_dir])                

                # Switch to Month-sort if needed
                if first_line and not first_line[0].isdigit():
                    sort_cmd = ["sort", "-M", "-k1,1", "-k2,2n", "-k3,3"] + sort_cmd[1:]

                subprocess.run(sort_cmd, check=True)

                percent = (i / len(log_files)) * 100
                print(f"[SORTING: {percent:6.2f}%] {i}/{len(log_files)} | {os.path.basename(path)[:30]:<30}", end='\r')

            # We still hash the files for the digest, even if we didn't sort them
            if no_hash:
                digest_lines.append(f"{path} | Size: {os.path.getsize(path)} | HASH SKIPPED\n")
            else:            
                stats = get_file_stats(path)
                digest_lines.append(f"{path} | Size: {stats['size']} | SHA256: {stats['sha256']}\n")

        except Exception as e:
            print(f"\nWarning: Error processing {path}: {e}")

    # --- Archiving Phase ---
    if no_compress:
        print("\n[!] --no-compress detected. Skipping .tar.xz creation.")
    else:    
        tar_filename = f"{os.path.normpath(output_dir)}.tar.xz"
        print(f"Creating compressed archive: {tar_filename}...")
        with tarfile.open(tar_filename, "w:xz", preset=9) as tar:
            tar.add(output_dir, arcname="output", filter=reset_metadata)
        try:
            # Capture xz -l output
            xz_list = subprocess.check_output(["xz", "-l", tar_filename],
                                              text=True,
                                              stderr=subprocess.STDOUT)

            digest_lines.append("\n--- ARCHIVE LISTING (xz -l) ---\n")
            digest_lines.append(xz_list)
            digest_lines.append("-" * 30 + "\n")

        except Exception as e:
            digest_lines.append(f"\n[!] Warning: Could not run xz -l: {e}\n")

    # --- Capture Finish Time ---
    finish_time = datetime.now()
    duration = finish_time - start_time

    # --- Final Digest Update ---
    digest_lines.append("\n--- FINAL SUMMARY ---\n")
    digest_lines.append(f"Processing Finish Time: {finish_time}\n")
    digest_lines.append(f"Total Execution Duration: {duration}\n")
    if not no_compress:
        try:
            archive_stats = get_file_stats(tar_filename)
            digest_lines.append(f"Archive: {tar_filename} | Size: {archive_stats['size']} |"
                                f" MD5: {archive_stats['md5']} | SHA256: {archive_stats['sha256']}\n")
        except NameError:
            # Fallback if the variable was never even declared
            digest_lines.append("Archive: Not created (compression skipped).\n")
    else:
        digest_lines.append("Archive: Compression skipped by user flag.\n")

    digest_path = f"{output_dir}_digest.txt"
    with open(digest_path, "w", encoding="utf-8") as df:
        df.writelines(digest_lines)
    print(f"Digest generated: {digest_path}")
    print(f"Processing complete in {datetime.now() - start_time}")

if __name__ == "__main__":
    # Define paths relative to the script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_conf = os.path.join(script_dir, "", "splitters.conf")
    
    # Load metadata for CLI generation
    try:
        with open(default_conf, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception:
        metadata = []

    parser = argparse.ArgumentParser(description="Forensic Log Splitter")
    # Basic Arguments
    parser.add_argument("input_dir", help="Input logs path")
    parser.add_argument("output_dir", help="Output logs path")
    parser.add_argument("--conf", default=default_conf, help="Path to config (default: splitters.conf)")
    
    # Simple Options (Dynamic Flags)
    group = parser.add_argument_group("Splitter Modules (Simple Mode)")
    for item in metadata:
        group.add_argument(f"--split_by_{item['name']}", action="store_true", 
                           help=item.get("description", f"Split by {item['name']}"))
    parser.add_argument("--list-modules", action="store_true", help="Show all available modules and exit")
    # Expert Options
    expert = parser.add_argument_group("Expert Options")
    expert.add_argument("--processes", type=int, default=cpu_count())
    expert.add_argument("-i", "--ignore-case", action="store_true")
    expert.add_argument("--no-sort", action="store_true")
    expert.add_argument("--no-hash", action="store_true")
    expert.add_argument("--no-compress", action="store_true")
    expert.add_argument("--tmp-dir", default=None)
    expert.add_argument("--sort-mem", default="80%", help="Memory buffer for sort, e.g., '32G' or '80%%' (default: 80%%)") # Remember the double %%
    
    args = parser.parse_args()

    if args.list_modules:
        print(f"{'Module':<20} | {'Description'}")
        print("-" * 50)
        for item in metadata:
            print(f"{item['name']:<20} | {item.get('description', 'N/A')}")
        sys.exit(0)

    # Pass args to main
    main(args.input_dir, args.output_dir, args.processes, args.ignore_case, 
         args.no_sort, args.conf, args.no_hash, args.no_compress, 
         args.tmp_dir, args.sort_mem, args)    
#TODO
#Check if digest shows input files even without hashing
#Add --no-digest option
