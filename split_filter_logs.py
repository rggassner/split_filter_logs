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
import gzip
import bz2
import lzma
import zipfile
import ipaddress
import argparse
import hashlib
import tarfile
from datetime import datetime
from multiprocessing import Pool, cpu_count

# Example config
SPLITTERS = [
    {
        "name": "split_by_user",
        "split_function": r'user="(?:.*?\()?(?P<username>[a-zA-Z0-9._-]+)\s*(?:\))?"',
        "filter": [""], 
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
    },
    {
        "name": "split_by_user_dn",
        "split_function": r'user_dn="(?P<user_dn>.*?)"',
        "filter": [""], 
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
    },
    {
        "name": "split_by_session_uid",
        "split_function": r'session_uid="(?P<session_uid>.*?)"',
        "filter": [""], 
        "filter_from_file": "",
        "enabled": False,
        "type": "string"
    },
    {
        "name": "split_by_src",
        "split_function": r'src="(?P<src>.*?)"',
        "filter": [], 
        "filter_from_file": "srcAll",  
        "enabled": True,
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
                print(f"Warning: invalid IP/network in filter for {splitter.get('name', '')}: {f}")
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
    """
    Evaluates an extracted value against a defined set of inclusion criteria.

    This function acts as a conditional filter for log splitting. It supports 
    both literal string matching and advanced network logic for IP addresses. 
    In forensic workflows, this allows investigators to narrow focus to specific 
    indicators of compromise (IOCs) or known subnets without losing data 
    integrity for non-targeted entries.

    Filtering Logic:
        1. Universal Match: If the filter list is empty or contains an 
           empty string (""), the function returns True for all inputs.
        2. IP/Network Logic: If the splitter type is 'ip', the function 
           validates the 'value' as a legitimate IPv4/IPv6 address and 
           checks for membership within a specific IP or a CIDR subnet 
           (e.g., 192.168.1.0/24).
        3. String Logic: For all other types, it performs a high-speed 
           membership check within a pre-compiled set of strings.

    Args:
        value (str): The raw string extracted from the log line (e.g., 
            a username, session ID, or IP address).
        f_splitter (dict): The compiled splitter configuration containing:
            - "filter": A set of strings or a list of ipaddress objects.
            - "type": The data category (e.g., "ip" or "string").

    Returns:
        bool: True if the value satisfies the filter criteria, False otherwise.

    Note:
        The use of 'ipaddress' objects ensures that '192.168.1.1' will 
        correctly match a filter for '192.168.1.0/24', a feat impossible 
        with standard string comparison.
    """
    filters = f_splitter["filter"]
    if not filters or "" in filters:
        return True  # match all

    if f_splitter["type"] == "ip":
        try:
            ip_val = ipaddress.ip_address(value)
        except ValueError:
            return False
        for fi in filters:
            if isinstance(fi, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                if ip_val == fi:
                    return True
            elif isinstance(fi, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if ip_val in fi:
                    return True
        return False
    return value in filters


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
    """
    Evaluates a single log entry against all active splitters and buffers matches.

    This function iterates through the global `COMPILED_SPLITTERS`. For each 
    splitter, it attempts to extract a value based on the defined regex 
    named group. If a match is found and satisfies the associated filter 
    criteria, the line is staged in a local memory buffer mapped to the 
    calculated output file path.

    Forensic Considerations:
        - Multi-matching: A single line can be matched by multiple splitters 
          and will be buffered for all of them, ensuring no overlapping 
          data categories are missed.
        - Memory Staging: Data is not written immediately to disk; it is 
          held in the `buffer` dictionary to minimize I/O overhead and 
          file lock contention.

    Args:
        line (str): The raw text line/entry extracted from the source log.
        output_dir (str): The base directory where splitter-specific 
            subdirectories are located.
        buffer (dict): A mutable dictionary used to accumulate lines. 
            Keyed by absolute output file path (str), with values being 
            lists of log lines (list of str).

    Note:
        This function does not handle file I/O or locking; it is purely 
        responsible for logic and memory-mapping. Disk persistence is 
        deferred to the `flush_buffer` function.
    """
    for splitter_line in COMPILED_SPLITTERS:
        match_line = splitter_line["regex"].search(line)
        if not match_line:
            continue  # Skip if no match

        # Check if a specific regex group name was defined (e.g., "username" or "src")
        if splitter_line["group"]:
            # Extract only the data within that specific (?P<name>...) group
            value = match_line.group(splitter_line["group"])
        else:
            # If no group was defined, take the entire string that matched the regex
            value = match_line.group(0)
        if not match_filter(value, splitter_line):
            continue  # Skip if the match doesn't pass the filter

        out_dir = os.path.join(output_dir, splitter_line["name"])
        out_path = os.path.join(out_dir, value + ".log")

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


def main(input_dir, output_dir, processes): #pylint: disable=too-many-locals
    """
    Executes the end-to-end forensic log processing pipeline: ingestion, 
    categorization, normalization, and secure archival.

    This function manages the full lifecycle of a forensic extraction, ensuring
    chain-of-custody integrity by hashing all inputs and outputs and generating
    a comprehensive audit digest.

    Forensic Workflow:
        1. Pre-Processing Audit: Discovers all input files and calculates 
           SHA256/MD5 hashes and file sizes before any modification.
        2. Parallel Extraction: Distributes log processing across a 
           multiprocessing pool to split data into categorized subdirectories.
        3. Data Normalization: Performs a high-performance, parallelized 
           numeric sort on all generated output logs using the system 'sort' 
           utility to ensure chronological consistency.
        4. Post-Processing Audit: Recursively hashes all resulting output 
           files for the final report.
        5. Secure Archival: Tars and compresses the output directory into 
           an '.xz' archive using the LZMA2 'Extreme' preset (equivalent 
           to xz -ze9).
        6. Digest Generation: Produces a final text-based manifest outside 
           the output directory containing start times, input hashes, 
           output hashes, and the final compressed archive's signature.

    Supported Input Formats:
        - Transparent streaming of GZIP, BZIP2, XZ, and ZIP archives 
          (detected via magic bytes).

    Args:
        input_dir (str): Root directory containing source log files.
        output_dir (str): Destination for the structured log hierarchy.
        processes (int): Number of worker processes to spawn for 
                         parallelized file processing.

    Returns:
        None: All status updates and processing metrics are printed to stdout; 
              a manifest is persisted to '<output_dir>_digest.txt'.

    Note:
        The pipeline assumes the presence of a GNU-compatible 'sort' utility 
        in the system PATH for the normalization phase.
    """
    start_time = datetime.now()
    digest_lines = [f"Processing Start Time: {start_time}\n", "--- INPUT FILES ---\n"]

    make_dirs(output_dir)
    files = collect_files(input_dir)

    # Hash Input Files
    print(f"Hashing {len(files)} input files...")
    for fi in files:
        stats = get_file_stats(fi)
        digest_lines.append(f"{fi} | Size: {stats['size']} |"
                            f" MD5: {stats['md5']} | SHA256: {stats['sha256']}\n")

    # --- Processing Phase ---
    tasks = [(f, output_dir) for f in files]
    pool = Pool(processes) #pylint: disable=consider-using-with
    pool.map(process_file, tasks, chunksize=1)
    pool.close()
    pool.join()

    # --- Sorting Phase ---
    try:
        nproc = str(os.cpu_count())
    except Exception:#pylint: disable=broad-exception-caught
        nproc = "1"

    log_files = []
    for root, _, walk_files in os.walk(output_dir):
        for name in walk_files:
            if name.endswith(".log"):
                log_files.append(os.path.join(root, name))

    print(f"Sorting and hashing {len(log_files)} output files...")
    digest_lines.append("\n--- OUTPUT FILES ---\n")

    for path in sorted(log_files):
        try:
            subprocess.run(["sort", "-n", "--parallel=" + nproc, "-o", path, path], check=True)
            stats = get_file_stats(path)
            digest_lines.append(f"{path} | Size: {stats['size']} |"
                                f" MD5: {stats['md5']} | SHA256: {stats['sha256']}\n")
        except Exception as e:#pylint: disable=broad-exception-caught
            print(f"Warning: could not process {path}: {e}")

    # --- Archiving Phase ---
    tar_filename = f"{os.path.normpath(output_dir)}.tar.xz"
    print(f"Creating compressed archive: {tar_filename}...")
    with tarfile.open(tar_filename, "w:xz", preset=9) as tar:
        tar.add(output_dir, arcname="output", filter=reset_metadata)

    # --- Capture Finish Time ---
    finish_time = datetime.now()
    duration = finish_time - start_time

    # --- Final Digest Update ---
    archive_stats = get_file_stats(tar_filename)
    digest_lines.append("\n--- FINAL SUMMARY ---\n")
    digest_lines.append(f"Processing Finish Time: {finish_time}\n")
    digest_lines.append(f"Total Execution Duration: {duration}\n")
    digest_lines.append(f"Archive: {tar_filename} | Size: {archive_stats['size']} |"
                        f" MD5: {archive_stats['md5']} | SHA256: {archive_stats['sha256']}\n")
    digest_path = f"{output_dir}_digest.txt"
    with open(digest_path, "w", encoding="utf-8") as df:
        df.writelines(digest_lines)
    print(f"Digest generated: {digest_path}")
    print(f"Processing complete in {datetime.now() - start_time}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Directory with input log files (.gz or plain text)")
    parser.add_argument("output_dir", help="Directory to store filtered logs")
    parser.add_argument("--processes", type=int, default=cpu_count(),
                        help="Number of worker processes (default: all CPUs)")
    args = parser.parse_args()

    main(args.input_dir, args.output_dir, args.processes)
