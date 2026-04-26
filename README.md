# Forensic Log Splitter

A high-performance, modular log processing tool designed for large-scale forensic analysis.
It ingests raw or compressed logs, extracts relevant data using configurable rules, and outputs organized, filtered, and optionally sorted results.

## Features

* Multi-format input support:

  * Plain text
  * gzip (.gz)
  * bzip2 (.bz2)
  * xz/lzma (.xz)
  * zip (.zip)

* Parallel processing:

  * Multi-core hashing and processing
  * Efficient buffering to reduce disk I/O

* Flexible splitting engine:

  * Regex-based extraction
  * String-based matching
  * IP and CIDR filtering
  * Case-sensitive or insensitive modes

* Modular configuration:

  * JSON-based splitter definitions
  * Optional external filter files

* Output handling:

  * Automatic directory organization by splitter
  * Buffered writes with file locking
  * Optional chronological sorting

* Integrity and traceability:

  * MD5 and SHA256 hashing
  * Full execution digest report

* Archiving:

  * Optional `.tar.xz` compression with reproducible metadata

## Project Structure

```
.
├── script.py
├── splitters.conf
├── splitters/
│   ├── module1.txt
│   ├── module2.txt
│   └── ...
```

## Installation

No external Python dependencies are required beyond the standard library.

Ensure the following system tools are available:

* sort (GNU coreutils)
* xz

## Usage

Basic usage:

```
python3 script.py <input_dir> <output_dir>
```

Example:

```
python3 script.py ./logs ./output
```

## Command-Line Options

### Basic

* `input_dir`
  Directory containing input log files

* `output_dir`
  Directory where processed logs will be stored

* `--conf`
  Path to configuration file (default: `splitters.conf`)

### Splitter Modules (Simple Mode)

Enable specific modules:

```
--split_by_<module_name>
```

Example:

```
--split_by_ip --split_by_email
```

List available modules:

```
--list-modules
```

### Expert Options

* `--processes <int>`
  Number of parallel processes (default: CPU count)

* `-i, --ignore-case`
  Enable case-insensitive matching

* `--no-sort`
  Skip sorting output files

* `--no-hash`
  Skip hashing input files

* `--no-compress`
  Skip archive creation

* `--tmp-dir <path>`
  Temporary directory for sorting

* `--sort-mem <value>`
  Memory buffer for sort (e.g., `32G`, `80%`)

## Configuration

The `splitters.conf` file defines how logs are processed.

Each splitter includes:

* `name`
  Identifier for output grouping

* `type`
  One of:

  * `string`
  * `start_string`
  * `global_string`
  * `ip`

* `split_function`
  Regex with named capture group

* `filter`
  Inline filter values

* `filter_from_file`
  External file with filter values

* `enabled`
  Boolean to activate/deactivate

### Example

```
{
  "name": "ip",
  "type": "ip",
  "split_function": "(?P<ip>\\b\\d+\\.\\d+\\.\\d+\\.\\d+\\b)",
  "filter_from_file": "splitters/ip.txt",
  "enabled": true
}
```

## Processing Pipeline

1. Configuration loading
2. Optional hashing of input files
3. Parallel log processing and filtering
4. Buffered output writing
5. Optional sorting of output files
6. Optional archive generation
7. Digest report creation

## Output

The tool generates:

* Structured log files:

  ```
  output/
    ├── <splitter_name>/
    │   ├── value1.log
    │   ├── value2.log
  ```

* Digest file:

  ```
  <output_dir>_digest.txt
  ```

* Optional archive:

  ```
  <output_dir>.tar.xz
  ```

## Digest Contents

* Input file metadata (size, hashes)
* Output file metadata
* Archive details
* Execution timestamps
* Total duration

## Performance Considerations

* Uses streaming reads to handle large files
* Buffered writes reduce disk contention
* Parallel execution scales with CPU cores
* Sorting leverages system `sort` for efficiency

## Error Handling

* Invalid filters are logged as warnings
* Missing required filter files cause immediate termination
* Unsupported file formats are skipped unless strict mode is enforced

## Known Limitations

* Relies on external `sort` and `xz` utilities
* Memory usage during sorting depends on system configuration
* ZIP processing reads files sequentially without parallelism

## TODO

* Add `--no-digest` option
* Improve digest behavior when hashing is disabled

## License

This project is provided as-is for forensic and analytical use.
