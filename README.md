# Forensic Log Splitter & Filter

A high-performance, parallelized Python utility designed for large-scale forensic log ingestion. This tool allows users to split massive log files (including `.gz` archives) into organized structures based on regex patterns, filter the data against specific watchlists, and perform chronological sorting.

## Features

-   **Parallel Processing:** Multi-core hashing, extraction, and filtering for maximum throughput.
-   **Forensic Integrity:** Generates a standalone forensic digest with MD5/SHA256 hashes for all input and output files.
-   **Large File Optimization:** Uses external merge sort with configurable memory buffers and temporary directory paths to handle files larger than system RAM (e.g., 40GB+).
-   **Flexible Modes:**
    
    -   **Simple Mode:** Quick execution using pre-defined modules and auto-linked filter files.
    -   **Expert Mode:** Full control via JSON configuration for complex, nested regex splitting.
-   **Archive Ready:** Automatically creates compressed `.tar.xz` packages with integrity metadata.

* * *

## Directory Structure

For the script to operate in **Simple Mode**, maintain the following organization:

Plaintext

```
.
├── split_filter_logs.py
├── splitters.conf           # Metadata for all modules
└── splitters/
    ├── src_ip               # Filter list for src_ip module
    └── user_name            # Filter list for user_name module
```

* * *

## Usage

### 1\. Simple Mode

Perfect for daily tasks. Use pre-defined flags to activate specific splitting modules. The script will automatically look for matching filter files in the `splitters/` directory.

Bash

```
# Split logs by Source IP using the pre-defined module
./split_filter_logs.py /path/to/input /path/to/output --split_by_src_ip

# List all available simple modules
./split_filter_logs.py --list-modules
```

### 2\. Expert Mode

For complex investigations requiring specific resource management and custom configurations.

Bash

```
./split_filter_logs.py /data/in /data/out \
    --conf my_investigation.json \
    --sort-mem 32G \
    --tmp-dir /data/working_scratch \
    --processes 16
```

* * *

## Advanced CLI Options

| Option | Description | Default |
| --- | --- | --- |
| `--conf` | Path to the JSON configuration file | `splitters.conf` |
| `--processes` | Number of CPU cores to utilize | All available |
| `--no-sort` | Skip the chronological sorting phase | False |
| `--no-hash` | Skip MD5/SHA256 integrity checks | False |
| `--no-compress` | Skip final `.tar.xz` creation | False |
| `--tmp-dir` | Directory for large file sorting "swap" | System `/tmp` |
| `--sort-mem` | RAM buffer for sorting (e.g., `80%` or `32G`) | `80%` |

Export to Sheets

* * *

## Forensic Digest

Upon completion, the script generates an `[output]_digest.txt`. This file is the **Source of Truth** for the operation, containing:

1.  **Input Manifest:** Hashes of all raw source files.
2.  **Output Manifest:** Hashes of every split log created.
3.  **Archive Metadata:** `xz -l` compression stats and the hash of the final `.tar.xz` container.
4.  **Audit Trail:** Start/Finish timestamps and total execution duration.

* * *

## Configuration (JSON)

Each module in the configuration follows this schema:

JSON

```
{
    "name": "src_ip",
    "split_function": "^\\d+\\.\\d+\\s+\\d+\\s+(?P<val>\\d{1,3}(?:\\.\\d{1,3}){3})",
    "type": "ip",
    "description": "Splits logs by extracted Source IPv4 address"
}
```

* * *

## Requirements

-   **Python:** 3.12+
-   **System Utilities:** `sort` (GNU Coreutils), `xz`
-   **Recommended Hardware:** SSD/NVMe storage for high-IOPS sorting phases.



