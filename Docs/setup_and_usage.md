# Usage Guide

## Run the Tool

```bash
python main.py
```
---
## After running the tool in PowerShell, it will prompt a series of questions.

### API Key Configuration

If the user has not configured an API key, the tool will ask:

`There is no API key present. Do you want to add one? (Yes/No) :`

If the user selects Yes:

The tool will prompt to enter the Hybrid Analysis API key.

If the user selects No:

The tool will skip API configuration and continue to the next step without using Hybrid Analysis.


## Output Directory

`Enter the output directory name to store generated results : `

- This prompt helps to specify where the generated output will be saved  
- The tool creates a new folder in the current directory using the given name  
- The directory name must be unique

## Investigator Name

`Enter the investigator’s name : `

- This is used for reference purposes (to identify who is running the scan)  
- It does not affect the tool’s functionality or performance

## Investigation Time Range

`How many days back should the investigation begin? (e.g., 1) :`

- This prompt defines how far back the tool should collect artifacts  
- The tool will gather data from the specified number of days up to the current time  

Example:
- Input: `3`  
- Meaning: Collect artifacts from 3 days ago until now  

## Firewall Log Selection

`Choose which firewall logs to collect (TCP / UDP / Both) :`

- This prompt specifies which firewall logs the tool should collect  
- You can choose to collect:
  - `TCP` logs only  
  - `UDP` logs only  
  - `Both` TCP and UDP logs
 
## Expected Connection Count (Firewall Logs)

`What is the expected inbound and outbound connection count for each IP? (Enter 0 if unknown) : `

- This prompt sets a baseline for normal network activity per IP  
- The tool uses this value to identify unusual or suspicious connection patterns  
- Enter `0` if the expected value is unknown

## Recursive File Analysis

`Do you want to continue the file analysis recursively? (yes or no) :`

- This prompt controls whether the tool should analyze files in subdirectories  
- `yes` → The tool will scan all nested folders recursively  
- `no` → The tool will scan only the current directory

## Hash Storage

`Do you want to save the recent hashes (yes or no) :`

- The framework stores hash values of known legitimate applications (whitelist)  
- During analysis, if such hashes are identified, the tool can save them for future reference  

- `yes` → Saves the hashes, which can help reduce scan time in future runs  
- `no` → Does not store hashes; each scan will process everything again

## Scan Execution and Output

After providing all inputs, the tool will start the scanning process.

- Each module runs sequentially  
- After each scan, the tool displays the status and generates a corresponding HTML report.
- Note: Each module may take a different amount of time; some may complete quickly, while others may take longer depending on the data being processed  

---

## Scan Progress (Console Output)

```text i
[+] Index File generated

[+] Basic Information collection scan completed
HTML report generated : Basic System Scan

[+] Live Connection artifacts scan completed
HTML report generated: Live Network Connections

[+] Firewall artifacts scan completed
HTML report generated: Firewall Artifacts

[+] Prefetch artifacts scan completed
HTML report generated: Prefetch artifacts

[+] ScheduleTask artifacts scan completed
HTML report generated: Schedule artifacts

[+] Services artifacts scan completed

[+] Startup Folders artifacts scan completed

[+] Registry artifacts scan completed

HTML report generated: Services artifacts
HTML report generated: Startup Folders artifacts
HTML report generated: Registry artifacts

[+] Running task artifacts scan completed
HTML report generated: Running task

[+] Browser Artifacts collection scan completed
HTML report generated : Browser Artifacts

[+] Files Information scan completed
HTML report generated: File System artifacts

[+] Windows Defender Log collection scan completed
HTML report generated: Windows Defender Artifacts

[+] USB Artifacts scan completed
HTML report generated: USB device artifacts

 Artifact Analysis Completed Successfully
 
```
