class SnippetStore:
    def __init__(self):
        self.db_dict = {

            "Heading":"The system’s general information is provided below.",
            "user_title1":"List of users present on the system.",
            "user_title2": "User accounts were identified as members of the local Administrators group, indicating elevated administrative privileges on the host.",
            "user_title3": "List of network adapters present on the system",
            "user_title4": "Windows Defender status verification",
            "user_title5": "System Network Interfaces and IP Addresses",
            "user_title6": "Firewall Log status",
            "user_title7": "Windows Operating System Version and Build Details",
            "User_title8": "How many Partitions and Disks Present in this system"

        }

        self.pref_db = {

            "Heading":"Analysis of Windows Prefetch Execution Artifacts",
            "first_para":"Windows Prefetch files record application execution details, including the program name, executable path, and last execution time, and are primarily used by the operating system to improve application load performance.",
            "second_para": "Executable hashes extracted from Prefetch files were checked using Hybrid Analysis. Legitimate files were omitted from the report, while all raw Prefetch evidence was retained in the Core Evidence directory.",
            "csv_name" : "pro_prefetch_evi.csv"
        }


        self.service_db = {

            "Heading":"Analysis of Windows Service  Artifacts",
            "first_para":"A service artifact is a persistent system trace created when a service is installed, modified, or executed, allowing attackers to maintain persistence by automatically restarting malicious processes after a system reboot.",
            "second_para": "A service artifact can be abused by threat actors as a persistence mechanism, enabling malicious binaries to run with elevated privileges and automatically restart on every system boot. Such artifacts often indicate long-term compromise and are commonly used to maintain access, evade detection, and survive reboots.",
            "csv_name" : "proc_srv.csv"
        }

        self.startup_db = {

            "Heading":"Analysis of Windows Startup Folder Artifacts",
            "first_para":"Startup folder artifacts are traces created when programs or scripts are configured to run automatically at logon or system startup. These artifacts include executables, shortcuts, or scripts placed in Startup directories, enabling persistence across reboots.",
            "second_para": "They exist in two types: User Startup artifacts, which trigger execution when a specific user logs in, and System Startup artifacts, which execute for all users at boot. Threat actors abuse both to maintain persistence with minimal visibility and survive system restarts.",
            "csv_name" : "startups.csv"
        }

        self.live_task_db = {

            "Heading":"Analysis of  Active System Processes Artifacts",
            "first_para":"This module enumerates all processes currently running on the system at the time of acquisition. The collected data includes process identifiers and available executable paths, providing a snapshot of active system activity for forensic correlation and analysis.",
            "second_para": "Processes that are identified as legitimate through Hybrid Analysis are excluded from the final analytical report to reduce noise and false positives. However, all process artifacts—including verified legitimate entries—are preserved in the core evidence files within the output directory to maintain evidence integrity and allow independent verification if required.",
            "csv_name" : "pro_live_task_evi.csv"
        }

        self.TCP = {

            "Heading": "Analysis of  Live System Connection Artifacts",
            "Title"  : "Live TCP Connections",
            "first_para": "TCP connection artifacts capture session-based network communications, detailing connection state, remote address, remote port, and owning process at the time of collection.",
            "second_para": "TCP connection data is collected using the Windows Get-NetTCPConnection cmdlet, enabling correlation between network sessions and process identifiers.",
            "csv_name": "TCP_With_path.csv"

        }

        self.UDP = {

            "Heading": "Analysis of  Live System Connection Artifacts",
            "Title"  : "Live UDP Connections",
            "first_para": "TCP connection artifacts capture session-based network communications, detailing connection state, remote address, remote port, and owning process at the time of collection.",
            "second_para": "TCP connection data is collected using the Windows Get-NetTCPConnection cmdlet, enabling correlation between network sessions and process identifiers.",
            "csv_name": "UDP_With_path.csv"

        }

        self.firewall_outbound = {
            "Heading":"Analysis of Firewall Log Artifacts",
            "Title":"Outbound Connection",
            "first_para":"Windows Firewall Log Artifact Analysis involves reviewing firewall-generated logs to track inbound and outbound network connections. These logs record key details such as IP addresses, ports, protocols, timestamps, and allow/block actions. Analyzing them helps detect suspicious traffic, unauthorized access attempts, and rule misconfigurations, supporting incident response and system hardening.",
            "second_para":"Windows Firewall Log Artifact Analysis focuses on examining firewall logs related only to outbound network traffic. This section covers destination IP addresses, destination ports, protocols, timestamps, and allowed actions for outgoing connections. Analyzing outbound traffic helps identify suspicious external communications, malware callbacks, data exfiltration attempts, and misconfigured application behavior.",
            "csv_name": "outbound_traffic.csv"
        }

        self.firewall_inbound = {
            "Heading":"Analysis of Firewall Log Artifacts",
            "Title":"Inbound Connection",
            "first_para":"Windows Firewall Log Artifact Analysis involves reviewing firewall-generated logs to track inbound and outbound network connections. These logs record key details such as IP addresses, ports, protocols, timestamps, and allow/block actions. Analyzing them helps detect suspicious traffic, unauthorized access attempts, and rule misconfigurations, supporting incident response and system hardening.",
            "second_para":"Windows Firewall Log Artifact Analysis focuses on examining firewall logs related only to outbound network traffic. This section covers destination IP addresses, destination ports, protocols, timestamps, and allowed actions for outgoing connections. Analyzing outbound traffic helps identify suspicious external communications, malware callbacks, data exfiltration attempts, and misconfigured application behavior.",
            "csv_name": "inbound_traffic.csv"
        }

        self.registry = {

            "Heading": "Windows Registry File Artifacts",
            "first_para":"Windows Registry files are examined during analysis because attackers commonly use them to achieve persistence. By creating or modifying specific registry keys, malware can automatically execute on system startup or user logon, allowing it to survive reboots and maintain long-term access to the system.",
            "second_para":"For persistence analysis, investigators commonly check Run and RunOnce keys for both local user and system-wide execution. This includes user-level locations under the current user hive and system-level locations that apply to all users, as these keys are frequently abused to launch malicious executables, scripts, or DLLs during startup.",
            "csv_name" : "finalize_registry.csv"
        }

        self.browser = {

            "Heading": "Browser Artifacts",
            "first_para": "Browser download artifacts record details about files obtained through a web browser. These typically include the downloaded file name, the source URL, and the timestamp indicating when the download started. Such information is stored in browser databases and is valuable in digital forensics for reconstructing user activity, verifying file origins, and supporting timeline analysis during investigations.",
            "second_para": "Browser download activity artifacts contain records of files retrieved through the browser, including the file name, the download source link, and the start time of the transfer. These entries are usually maintained in internal browser databases and can be extracted for forensic analysis. They assist investigators in identifying user actions, tracing the origin of downloaded content, and correlating events within a system timeline.",
            "csv_name": "browser_artifacts.csv"


        }

        self.file = {

            "Heading": "System Files Artifacts",
            "first_para": "This module is designed to collect files from a specific target directory as part of the investigation process. The tool systematically traverses the selected directory path, identifies relevant files based on predefined criteria, and extracts them for further analysis. This approach ensures that only artifacts from the designated location are gathered, maintaining focus and reducing unnecessary data processing.",
            "second_para": "Additionally, the collection process is filtered based on a specified date range corresponding to the incident period. Only files that were created, modified, or accessed within the given timeframe are extracted. This time-bound acquisition enables investigators to concentrate on artifacts directly related to the incident, improving the efficiency and accuracy of the forensic analysis.",
            "csv_name": "dir_file.csv"


        }

        self.win_def = {
            "Heading": "Windows Defender Security Status Analysis",
            "first_para": "This section presents the analysis of Windows Defender artifacts to evaluate the security status of the system within the specified time frame. It identifies whether Windows Defender was disabled during the given number of days and, if so, records the most recent instance when the protection service was turned off.",
            "csv_name" : "windows_defender.csv"
        }

        self.real_time = {
            "Heading" : "Windows Defender Threat Detection and Action Records",
            "first_para" : "This section provides any malicious or potentially unwanted software detected by Windows Defender within the specified analysis period. It details the identified threat along with the corresponding remediation action taken, such as quarantine, removal, or blocking, as recorded in the system artifacts.",
            "csv_name" : "real_time.csv"

        }

        self.USB = {
            "Heading" : "Windows USB Connection Timeline Artifacts",
            "first_para" : "Windows USB device plug-in and plug-out time artifacts record when external USB devices were connected to and removed from a system. These timestamps help determine device usage patterns and user interaction with removable media. Such information is useful for building timelines and understanding external device activity during an investigation.",
            "csv_name" : "pro_USB_evi.csv"

        }