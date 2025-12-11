# LogSplitter — Parallel Log File Splitter & Filter

**LogSplitter** is a fast, multiprocessing Python tool for splitting large log directories into separate files based on user-defined regex extraction rules and filters.

It supports:

* Plain text and `.gz` compressed logs
* Filtering by IP addresses, networks, or string matches
* Multiple parallel workers for high-speed processing
* Per-field output directories with automatically created `.log` files

---

## Features

 **Regex-based extraction** — define any capture group to extract log fields like IPs, usernames, or hostnames.
 **IP-aware filters** — filter by address or CIDR ranges using built-in `ipaddress` logic.
 **Parallel processing** — uses all available CPU cores by default.
 **Handles `.gz` logs** seamlessly.
 **Automatic output organization** — creates one folder per splitter (e.g., `split_by_src/`, `split_by_dst/`) with one `.log` per extracted value.

---

## Example Use Case

Suppose you have network logs like this:

```
src="192.168.0.1" dst="8.8.8.8" user="admin"
src="10.0.0.5" dst="8.8.4.4" user="guest"
```

You can configure **LogSplitter** to:

* Extract and group logs by source or destination IP
* Filter only those matching a given IP range (e.g., `10.0.0.0/8`)
* Write results into folders like:

```
output/
├── split_by_src/
│   ├── 192.168.0.1.log
│   └── 10.0.0.5.log
└── split_by_dst/
    ├── 8.8.8.8.log
    └── 8.8.4.4.log
```

---

## Configuration

All split rules are defined in the `SPLITTERS` list at the top of the script.

Each splitter has:

```python
{
    "name": "split_by_src",             # Folder name under output_dir
    "split_function": r'src="(?P<src>.*?)"',  # Regex pattern with named group
    "filter": [],                       # Optional list of allowed values
    "filter_from_file": "src.filter",   # Optional file with one value per line
    "enabled": True,                    # Whether to activate this splitter
    "type": "ip"                        # 'ip' or 'string'
}
```

You can enable or disable any rule via the `enabled` field.

### Filter Files

When `filter_from_file` is set (e.g., `src.filter`), LogSplitter loads entries line by line.

* Lines starting with `#` are ignored.
* Empty lines match all.
* For IP types, supports single IPs and CIDR ranges (`192.168.0.0/24`).

---

## Usage

### Command-line

```bash
python3 logsplitter.py <input_dir> <output_dir> [--processes N]
```

**Arguments:**

* `input_dir`: Directory containing `.log` or `.gz` log files.
* `output_dir`: Where results are saved.
* `--processes`: (optional) Number of worker processes. Defaults to all CPU cores.

### Example

```bash
python3 logsplitter.py /data/logs /data/split_logs --processes 8
```

This will:

1. Traverse `/data/logs/` recursively
2. Read each file (supports `.gz`)
3. Apply all enabled regex splitters
4. Write matching lines into per-value `.log` files under `/data/split_logs/`

---

## Output Structure

```
output_dir/
├── split_by_src/
│   ├── 10.0.0.1.log
│   ├── 192.168.1.5.log
│   └── ...
├── split_by_dst/
│   ├── 8.8.8.8.log
│   └── ...
└── split_by_user/
    ├── admin.log
    ├── guest.log
```

---

## Performance

* Uses Python’s built-in `multiprocessing.Pool`
* Automatically detects and uses all CPU cores
* Efficient for huge directories of compressed or plain logs

---

## Dependencies

All dependencies are from the Python standard library:

```
os, re, gzip, ipaddress, multiprocessing, argparse
```

No installation required — works out of the box with **Python ≥ 3.7**

---

## 🩶 Example Filters

`src.filter`

```
# Internal network only
10.0.0.0/8
192.168.0.0/16
```

`dst.filter`

```
8.8.8.8
1.1.1.1
```

---

## Example Output

Each line that matches a splitter rule and passes the filter is appended to the corresponding log file.

For example:

```
output/split_by_src/192.168.0.1.log
```

contains:

```
src="192.168.0.1" dst="8.8.8.8" user="admin"
```


## License

This project is licensed under the **MIT License** — feel free to use, modify, and distribute.

## Tips

* To disable a splitter, set `"enabled": False`
* To match everything, use `"filter": [""]`
* `.gz` files are read transparently — no manual decompression needed
* If a regex doesn’t define a named group (`?P<name>`), the entire match is used as the key

## TODO

* Generate a hash_manifest.txt
* Guess an ETA based on total file sizes and already processed data.

---




> **LogSplitter** — Simple. Parallel. Reliable. Perfect for massive log archives.
