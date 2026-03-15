
# Windows Post-Incident Forensic Analyzer

A Python-based Windows forensic triage tool that automates the collection and analysis of system artifacts after a suspected security incident.

The framework gathers key forensic artifacts, performs basic enrichment such as hash verification and signature validation, and generates structured HTML reports to assist investigators during post-incident analysis.

---

## Features

- Automated Windows artifact collection
- Modular forensic scanning architecture
- SHA-256 hash generation for executables
- Digital signature verification
- Optional threat intelligence verification
- Structured CSV evidence storage
- HTML report generation for investigation

---

## Artifacts Collected

The framework analyzes several Windows forensic artifacts including:

- System information
- Live running processes
- Live network connections
- Firewall logs
- Prefetch execution artifacts
- Persistence mechanisms
  - Startup folder entries
  - Newly created services
  - Registry Run keys
- USB device activity
- Browser download artifacts

---

## Project Structure

```
Scanner_modules/
forensic_tools/
html_templates/
dbs/
main.py
```

- **Scanner_modules** – Modules responsible for artifact collection  
- **forensic_tools** – External utilities used for specialized artifact parsing  
- **html_templates** – Templates used to generate HTML reports  
- **dbs** – Configuration and hash database storage  

---

## Installation

Install the required dependencies:

```
pip install -r requirements.txt
```

---

## Usage

Run the main program:

```
python main.py
```

The tool will collect forensic artifacts and generate output inside a structured output directory.

---

## Hybrid Analysis API Configuration

The framework supports optional threat intelligence enrichment using **Hybrid Analysis**.

To enable this feature:

1. Create an account on Hybrid Analysis.
2. Generate an API key from your account dashboard.
3. Add the API key inside the framework configuration.

Example configuration file:

```
dbs/config_file.py
```

Add your API key:

```
api_value = "your_hybrid_analysis_api_key"
```

If no API key is configured, the framework will continue to operate in **offline mode** without threat intelligence enrichment.

---

## Output Structure

The framework generates the following directories during execution:

- **Core_evidence** – Raw collected artifacts  
- **Processed_evidence** – Filtered and enriched evidence  
- **Reports** – Generated HTML forensic reports  
- **sysinfo** – Basic system information  

---


## Configuration

Some framework settings can be customized through the configuration file:

`dbs/config_file.py`

This file allows investigators to define whitelisted IP addresses and which directories for file analysis.
---

### Firewall Log Whitelisting

Certain IP addresses can be excluded from firewall analysis to reduce noise from trusted infrastructure.

Example configuration:

```
self.whitelisted_ips = {
"ip_address": {
'8.8.8.8',
'127.0.0.1',
'8.8.4.4',
'1.1.1.1',
'224.0.0.251',
'ff02::fb',
'::1'
}
}
```


These IP addresses will be ignored during firewall log analysis.

---

### Directory Configuration for File Analysis

Investigators can define directories that should be included in file analysis.

Example:
```
self.directory_config = {
"directories": [
"add//dir//here//",
"other//dir//"
]
}
```

The framework will analyze files within these directories and perform hash verification, signature validation, and threat intelligence checks where applicable.



## Documentation

Full official documentation for the framework will be added to this repository soon.

---

## Disclaimer

This tool is intended for educational and research purposes in digital forensics and incident response.
