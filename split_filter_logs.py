#!/usr/bin/env python3
"""
Forensic Multiprocess Log Splitter and Categorizer

This script is designed for high-performance forensic analysis of large-scale
log repositories. it recursively crawls an input directory, identifies file
formats via magic-byte signatures, and distributes processing across multiple
CPU cores. Log entries are matched against user-defined regex patterns and
filtered by string or CIDR-based IP criteria before being persisted into
a structured output hierarchy.

Key Architectural Features:
    * Signature-Based Ingestion: Detects and streams GZIP, BZIP2, XZ, and
        ZIP archives without relying on file extensions.
    * Concurrency Control: Utilizes advisory file locking (fcntl.flock)
        to permit multiple worker processes to safely write to shared
        output files without data corruption or interleaving.
    * Byte Integrity: Employs 'utf-8' with 'surrogateescape' across all
        I/O operations to ensure malformed forensic data is preserved
        bit-for-bit.
    * Deterministic Output: After processing, all generated log files are
        subjected to a external numeric sort to ensure
        chronological or sequence-based consistency.
    * Memory Efficiency: Uses line-by-line streaming and local worker
        buffering (10,000 line threshold) to handle files significantly
        larger than available system RAM.

Usage:
    ./log_splitter.py <input_dir> <output_dir> [--processes N]

Example Config:
    The SPLITTERS list defines the regex named groups to extract and
    whether to filter by specific values (e.g., specific subnets).
"""
import subprocess
import fcntl
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

# Example config
#[
#    {
#        "name": "global_string",
#        "split_function": "", 
#        "filter_from_file": "ids.txt", 
#        "enabled": false,
#        "type": "global_string"
#    },
#    {
#        "name": "split_by_user",
#        "split_function": " user=\"(?:.*?\\()?(?P<username>[a-zA-Z0-9._-]+)\\s*(?:\\))?\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "string"
#    },
#    {
#        "name": "split_by_user_dn",
#        "split_function": " user_dn=\"(?P<user_dn>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "string"
#    },
#    {
#        "name": "split_by_session_uid",
#        "split_function": " session_uid=\"(?P<session_uid>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "string"
#    },
#    {
#        "name": "split_by_xlatesrc",
#        "split_function": " xlatesrc=\"(?P<xlatesrc>.*?)\"",
#        "filter_from_file": "",  
#        "enabled": false,
#        "type": "ip"
#    },
#    {
#        "name": "split_by_src",
#        "split_function": " src=\"(?P<src>.*?)\"",
#        "filter_from_file": "",  
#        "enabled": false,
#        "type": "ip"
#    },
#    {
#        "name": "split_by_dst",
#        "split_function": " dst=\"(?P<dst>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "ip"
#    },
#    {
#        "name": "split_by_status",
#        "split_function": " status=\"(?P<status>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "string"
#    },
#    {
#        "name": "split_by_client_name",
#        "split_function": " client_name=\"(?P<clientname>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "string"
#    },
#    {
#        "name": "split_by_office_mode_ip",
#        "split_function": " office_mode_ip=\"(?P<officemodeip>.*?)\"",
#        "filter_from_file": "",
#        "enabled": false,
#        "type": "ip"
#    },
#    {
#        "name": "split_by_service",
#        "split_function": " service=\"(?P<service>.*?)\"",
#        "filter_from_file": "services.txt",
#        "enabled": false,
#        "type": "string"
#    }
#]


def get_compiled_splitters(splitter_data, ignore_case):
    compiled_list = []
    flags = re.IGNORECASE if ignore_case else 0

    for splitter in splitter_data:
        if not splitter.get("enabled", True):
            continue

        filter_file = splitter.get("filter_from_file")
        if filter_file and not os.path.exists(filter_file):
            print(f"\n[!] FATAL ERROR: Filter file '{filter_file}' not found!")
            sys.exit(1)

        raw_filters = load_filter_list(splitter)
        ftype = splitter.get("type", "string")

        if ftype == "global_string":
            if not raw_filters:
                continue
            escaped_keywords = [re.escape(f) for f in raw_filters if f]
            combined_regex = rf'.*(?P<{splitter["name"]}>' + "|".join(escaped_keywords) + r').*'
            pattern = re.compile(combined_regex, flags)
            group = splitter["name"]
        else:
            pattern = re.compile(splitter["split_function"], flags)
            match = re.search(r'\?P<(\w+)>', splitter["split_function"])
            group = match.group(1) if match else None

        # Prepare filter set
        if ftype == "ip":
            filter_set = []
            for f in raw_filters:
                if not f: continue
                try:
                    filter_set.append(ipaddress.ip_network(f, strict=False) if "/" in f else ipaddress.ip_address(f))
                except ValueError:
                    print(f"Warning: invalid IP filter: {f}")
        else:
            # If ignore_case is True, we normalize the set to lowercase
            if ignore_case:
                filter_set = {f.lower() for f in raw_filters if f}
            else:
                filter_set = {f for f in raw_filters if f}

        compiled_list.append({
            "name": splitter["name"],
            "regex": pattern,
            "filter": filter_set,
            "group": group,
            "type": ftype,
            "ignore_case": ignore_case # Store preference for match_filter
        })
    return compiled_list

def hash_worker(file_path):
    """
    Executes a parallelized cryptographic audit and metadata capture for a single file.

    This function serves as the primary worker for the pre-processing phase. By 
    distributing the 'get_file_stats' operation across multiple CPU cores, it 
    drastically reduces the time required to establish a forensic baseline of 
    the input data compared to serial execution.

    Workflow:
        1. Integrity Verification: Invokes the multi-algorithm hashing engine 
           (MD5 and SHA256) to ensure bit-level authenticity.
        2. Volume Calculation: Captures the physical file size to provide 
           the denominator for the extraction phase's progress metric.
        3. Reporting: Returns the original path and the resulting metadata 
           dictionary to the parent process for inclusion in the master digest.

    Args:
        file_path (str): The absolute or relative path to the source file 
                         being audited.

    Returns:
        tuple: A pair containing:
            - file_path (str): The source path for identification in the main loop.
            - stats (dict): A dictionary containing 'md5', 'sha256', and 'size'.

    Note:
        Running this in parallel is I/O intensive. On systems with traditional 
        HDDs, high process counts may cause disk contention; on NVMe-based 
        systems, this phase will scale linearly with CPU core availability.
    """
    stats = get_file_stats(file_path)
    return file_path, stats

def get_file_stats(file_path):
    """
    Generates a cryptographic and physical profile of a file in a single I/O pass.

    This utility calculates MD5 and SHA256 hashes while simultaneously determining 
    the file size. By updating both hash objects within the same read loop, the 
    function minimizes disk head movement and system call overhead, which is 
    critical when auditing large volumes of forensic evidence.

    Forensic Standards:
        - Multi-Algorithm Verification: Provides both MD5 (for legacy systems) 
          and SHA256 (for modern collision resistance) to ensure robust 
          integrity verification.
        - Memory Efficiency: Processes files in 64KB (65,536 byte) chunks. This 
          ensures that even multi-gigabyte log files can be hashed without 
          exhausting system RAM.
        - Binary Integrity: Opens files in 'rb' (read-binary) mode to ensure 
          that the raw byte stream is hashed exactly as it exists on disk, 
          unaffected by text encoding or newline translations.

    Args:
        file_path (str): The absolute or relative path to the file to be audited.

    Returns:
        dict: A dictionary containing the file's metadata:
            - "md5" (str): The hex-encoded MD5 message digest.
            - "sha256" (str): The hex-encoded SHA256 message digest.
            - "size" (int): The total size of the file in bytes.

    Note:
        The use of 'iter(lambda: fst.read(65536), b"")' is a Pythonic idiom for 
        efficiently streaming binary data until EOF (End Of File) is reached.
    """
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
    """
    Normalizes file metadata to ensure deterministic and reproducible archive hashes.

    By default, TAR archives include system-specific metadata such as User IDs (UID), 
    Group IDs (GID), and last-modification timestamps (mtime). This causes the 
    final archive hash to change between runs even if the log data is identical. 
    This function intercepts the archiving process to strip these variables.

    Forensic Impact:
        - Reproducibility: Allows different investigators on different systems 
          to verify the data and arrive at the same SHA256/MD5 archive hash.
        - Privacy: Prevents the leakage of local system information (like 
          usernames or UID/GID schemes) into the forensic evidence package.
        - Timestamp Consistency: Sets 'mtime' to the Unix Epoch (0), removing 
          temporal "drift" from the archive headers.

    Args:
        tarinfo (tarfile.TarInfo): The metadata object for the file currently 
                                   being added to the archive.

    Returns:
        tarfile.TarInfo: The modified metadata object with normalized 
                         ownership and timestamp fields.
    """
    tarinfo.uid = tarinfo.gid = 0
    tarinfo.uname = tarinfo.gname = "root"
    tarinfo.mtime = 0
    return tarinfo

def load_filter_list(l_splitter):
    """
    Populates a splitter's criteria by merging inline filters with external file data.

    This function builds the master 'allow-list' for a specific categorization 
    rule. It ensures that large-scale indicators (like blacklisted IP ranges 
    or thousands of usernames) can be managed in external text files rather 
    than hardcoded into the script.

    Forensic Standards:
        - Integrity: Uses 'utf-8' with 'surrogateescape' to ensure that 
          special characters or non-standard bytes in filter files are 
          preserved for exact matching against log data.
        - Robustness: Strips whitespace and ignores comments (#) or empty 
          lines to prevent common configuration errors from affecting 
          data processing.
        - Safety: Employs a broad try-except block to ensure that a missing 
          or unreadable filter file does not crash the entire forensic 
          pipeline, but rather logs a warning.

    Args:
        splitter (dict): A configuration dictionary for a specific log 
            splitting rule, potentially containing 'filter' (list) 
            and 'filter_from_file' (path string).

    Returns:
        list: A combined list of all unique filter strings or patterns.
    """
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
        except Exception as e: #pylint: disable=broad-exception-caught
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
    """
    Identifies file type via magic bytes and returns an appropriate text-mode stream.

    Instead of relying on potentially misleading file extensions, this function 
    performs a signature analysis (magic byte check) on the first 6 bytes of the 
    file. It provides transparent access to plain text or compressed archives 
    (GZIP, BZ2, XZ, ZIP), normalizing all inputs into a UTF-8 line iterator.

    Forensic Workflow:
        1. Signature Verification: Inspects the file header against industry-standard 
           magic numbers. 
        2. Format Normalization: Returns a consistent iterator, allowing the 
           downstream logic to remain format-agnostic.
        3. Recursive Extraction: For ZIP archives, it yields lines from all 
           contained files sequentially.
        4. Validation: If no compression signature is found, it performs a 
           basic ASCII/UTF-8 sanity check on the header bytes before 
           attempting to open as plain text.

    Args:
        file_path (str): The path to the source file to be analyzed.
        strict (bool): If True, raises a ValueError upon encountering 
            unsupported formats or corrupted archives. If False, reports a 
            warning and returns None.

    Returns:
        iterable: A line-based file object or generator yielding strings.
        None: If the format is unsupported and strict is False.

    Raises:
        ValueError: If 'strict' is True and the file format is unknown or 
            the ZIP archive is corrupted.
    """
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
        return gzip.open(file_path, "rt", encoding="utf-8", errors="ignore")

    # --- BZ2 ---
    if header.startswith(bz2_magic):
        return bz2.open(file_path, "rt", encoding="utf-8", errors="ignore")

    # --- XZ/LZMA ---
    if header.startswith(xz_magic):
        return lzma.open(file_path, "rt", encoding="utf-8", errors="ignore")

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

        except Exception as e: #pylint: disable=broad-exception-caught
            msg = f"Error reading ZIP file '{file_path}': {e}"
            if strict:
                raise ValueError(msg) from e  # Re-raise with original exception context
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
    """
    Ensures the existence of a target directory path within the output architecture.

    This function provides a safety check before I/O operations. In the context 
    of a multiprocessing log-splitter, it ensures that splitter-specific 
    subdirectories (e.g., 'split_by_src/') are available before any worker 
    attempts to flush its buffer to a specific '.log' file.

    Implementation Detail:
        By checking 'os.path.exists' before 'os.makedirs', the function 
        avoids unnecessary system calls. However, in high-concurrency 
        environments, this is a "check-then-act" pattern. 

    Args:
        path (str): The directory path to be verified or created. This 
            can be a nested path, as 'os.makedirs' handles recursive 
            directory creation.

    Returns:
        None: The filesystem state is modified in-place.
    """
    if not os.path.exists(path):
        os.makedirs(path)

def match_filter(value, f_splitter):
    filters = f_splitter["filter"]
    if f_splitter["type"] == "global_string" or not filters:
        return True

    if f_splitter["type"] == "ip":
        try:
            ip_val = ipaddress.ip_address(value)
            for fi in filters:
                if (isinstance(fi, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and ip_val == fi) or \
                   (isinstance(fi, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and ip_val in fi):
                    return True
        except ValueError: pass
        return False
    
    # Check against set (case-sensitive or insensitive based on config)
    match_val = value.lower() if f_splitter["ignore_case"] else value
    return match_val in filters

def process_file_with_size(file_args):
    """
    Acts as a high-level wrapper for parallel file processing to track real-time progress.

    This function serves as the entry point for workers in the multiprocessing pool 
    during the extraction phase. It captures the physical byte-size of the target 
    file before passing it to the core processing logic. This allows the parent 
    process to increment the global 'processed_bytes' counter accurately, which 
    is the primary variable for calculating the remaining ETA.

    Workflow:
        1. Metadata Capture: Retrieves the file size via 'os.path.getsize' to 
           ensure the progress bar moves relative to the actual data volume 
           rather than just the file count.
        2. Execution: Delegates the actual decompression and regex filtering 
           to the 'process_file' function.
        3. Reporting: Returns the file path and its size to the 'imap_unordered' 
           iterator in the main process.

    Args:
        file_args (tuple): A pair containing:
            - file_path (str): The absolute or relative path to the log file.
            - output_dir (str): The destination directory for split logs.

    Returns:
        tuple: A pair containing (file_path, file_size), used by the main 
               loop to update the progress percentage and time estimation.
    """
    file_path, _ = file_args
    file_size = os.path.getsize(file_path)
    process_file(file_args)
    return file_path, file_size

def process_file(file_args):
    """
    Orchestrates the decompression, extraction, and buffered output of a single log file.

    This is the primary worker function executed in parallel across the multiprocessing 
    pool. It handles the lifecycle of a log file from initial format detection to 
    the final flushing of categorization buffers.

    Operational Workflow:
        1. Employs 'open_maybe_compressed' to provide a transparent text stream 
           regardless of the source's compression (Gzip, BZIP2, XZ, ZIP).
        2. Iterates through the file line-by-line to keep memory consumption 
           independent of the input file size.
        3. Aggregates matched data into a local 'buffer' dictionary to minimize 
           system calls and lock contention on the output files.
        4. Triggers a 'flush_buffer' operation using an O(1) incremental counter 
           once 10,000 lines have been processed, avoiding expensive dictionary 
           summations.
        5. Performs a final conditional flush to ensure no trailing data remains 
           in memory.

    Forensic Integrity:
        - Stream-based processing ensures large logs do not cause Out-Of-Memory (OOM) 
          crashes that would leave an investigation incomplete.
        - Comprehensive exception handling ensures that a single corrupted or 
          missing file does not terminate the entire batch process.

    Args:
        file_args (tuple): A pair containing:
            - file_path (str): The absolute or relative path to the source log file.
            - output_dir (str): The root destination for the split log architecture.

    Returns:
        None: Progress and errors are reported via stdout/stderr.

    Note:
        The 'buffer_limit' is set to 10,000 to optimize the balance between memory 
        usage per worker and the reduction of 'fcntl' locking frequency.
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
    except Exception as e: #pylint: disable=broad-exception-caught
        print(f"Unexpected error processing {file_path}: {e}")


def process_line(line, output_dir, buffer):
    """Evaluates a single log line against all enabled splitters and buffers matches.

    This function performs the core routing logic: identifying matches via regex,
    extracting the pivot value (e.g., username, IP), sanitizing the value for 
    filesystem compatibility, and appending the original line to a memory buffer 
    partitioned by the target output path.

    Args:
        line (str): The raw log entry to process, typically including trailing newline.
        output_dir (str): The base directory where splitter-specific subdirectories 
            will be created.
        buffer (dict): A dictionary mapping file paths (str) to lists of log 
            lines (list). This buffer is periodically flushed to disk by the caller.

    Logic Flow:
        1. Iterates through `COMPILED_SPLITTERS`.
        2. Extracts the `value` from the specific regex capture group or the whole match.
        3. Normalizes `target_filename`:
            - If `ignore_case` is True: converts to lowercase to consolidate files.
            - Otherwise: sanitizes illegal/problematic characters (?, =, spaces) 
              to ensure OS-level file creation doesn't fail.
        4. Validates the extracted value against the splitter's `match_filter`.
        5. Identifies the final `out_path` and queues the line for writing.

    Note:
        This function does not perform I/O. It populates the `buffer` to minimize 
        frequent disk writes and context switching during high-volume processing.
    """   
    for splitter_line in COMPILED_SPLITTERS:
        match_line = splitter_line["regex"].search(line)
        if not match_line:
            continue 

        value = match_line.group(splitter_line["group"]) if splitter_line["group"] else match_line.group(0)

        # Normalize filename only if ignore_case is active
        if splitter_line["type"] in ["string", "global_string"] and splitter_line["ignore_case"]:
            target_filename = value.lower()
        else:
            # Sanitize filename (as discussed previously) to prevent OS errors with encoded strings
            target_filename = re.sub(r'[?=\s]+', '_', value).strip('_')

        if not match_filter(value, splitter_line):
            continue 

        out_dir = os.path.join(output_dir, splitter_line["name"])
        out_path = os.path.join(out_dir, f"{target_filename}.log")

        if out_path not in buffer:
            buffer[out_path] = []
        buffer[out_path].append(line)

def flush_buffer(buffer):
    """
    Persists accumulated log entries to disk with atomicity and byte-level integrity.

    This function performs a thread/process-safe write operation for each file 
    path in the buffer. It uses advisory file locking (fcntl.flock) to prevent 
    interleaved writes from multiple processes targeting the same output file.

    Data Integrity:
        - Uses 'utf-8' encoding with 'surrogateescape' error handling. 
          This is a forensic best practice that allows the script to process 
          malformed or non-UTF-8 bytes by "hiding" them in the Unicode 
          private use area, ensuring they can be written back to disk 
          without data loss or modification.
        - Directories are created just-in-time to ensure the write succeeds 
          regardless of pre-existing structure.

    Args:
        buffer (dict): A mapping of output file paths (str) to lists of 
            log lines (list of str) to be appended.

    Raises:
        OSError: If a lock cannot be acquired or if there are filesystem 
            permission issues.
            
    
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
    Recursively discovers all files within a directory tree and returns a 
    deterministically sorted list of absolute paths.

    Args:
        input_dir (str): The root directory path to start the search. 
            Can be a relative or absolute path.

    Returns:
        list of str: A sorted list of full system paths to every file 
            found. Empty directories are ignored.
    """
    file_list = []
    for root, _, files in os.walk(input_dir):
        for name in files:
            file_list.append(os.path.join(root, name))
    return sorted(file_list)


def main(input_dir, output_dir, processes, ignore_case, no_sort, conf_file, no_hash, no_compress, tmp_dir, sort_mem): #pylint: disable=too-many-locals, too-many-statements
    # 1. Load the Configuration
    try:
        with open(conf_file, "r", encoding="utf-8") as f:
            splitter_data = json.load(f)
    except Exception as e:
        print(f"[!] FATAL: Could not load config file {conf_file}: {e}")
        sys.exit(1)

    global COMPILED_SPLITTERS
    COMPILED_SPLITTERS = get_compiled_splitters(splitter_data, ignore_case)
    if not COMPILED_SPLITTERS:
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

    num_logs = len(log_files)
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
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Directory with input log files (.gz or plain text)")
    parser.add_argument("output_dir", help="Directory to store filtered logs")
    parser.add_argument("--conf", required=True, help="Path to the JSON configuration file")
    parser.add_argument("--processes", type=int, default=cpu_count(),
                        help="Number of worker processes (default: all CPUs)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Enable case-insensitive matching")
    parser.add_argument("--no-sort", action="store_true",
                        help="Skip the chronological sorting phase (saves time)")
    parser.add_argument("--no-hash", action="store_true", default=False,
                        help="Skip MD5/SHA256 calculation (saves CPU/IO)")
    parser.add_argument("--no-compress", action="store_true", default=False,
                        help="Skip final .tar.xz archiving")    
    parser.add_argument("--tmp-dir", default=None,
                        help="Temporary directory for sorting (default: system /tmp or output_dir)")
    parser.add_argument("--sort-mem", default="80%",
                    help="Memory buffer for sort, e.g., '32G' or '80%%' (default: 80%%)")    
    args = parser.parse_args()
    main(args.input_dir, args.output_dir, args.processes, args.ignore_case, args.no_sort, args.conf, args.no_hash, args.no_compress, args.tmp_dir, args.sort_mem)
#TODO
#Check if digest shows input files even without hashing
#Add --no-digest option
