import subprocess
import shutil
import os
import csv

class basic_system_info:
    def __init__(self,path,filtered_evidence):
        self.path = path
        self.filtered_evidence = filtered_evidence
        self.pc_users = []

    def collecting_info(self):
        subprocess.run(
            ["powershell", "-Command",
             f"Get-NetAdapter -Physical | "
             f"Select Name, Status, MacAddress | "
             f"Export-Csv '{self.path}\\3info.csv' -NoTypeInformation -Append"],
            shell=True,
            text=True
        )

        subprocess.run(
            ["powershell", "-Command",
             f"Get-LocalGroupMember -Group 'Administrators' | "
             f"Select Name, ObjectClass | "
             f"Export-Csv '{self.path}\\2info.csv' -NoTypeInformation -Append"],
            shell=True
        )

        subprocess.run(
            ["powershell", "-Command",
             f" Get-LocalUser | select Name,SID,Enabled,Description | "
             #f"Select Name, Domain, SID | "
             f"Export-Csv '{self.path}\\1info.csv' -NoTypeInformation -Append"],
            shell=True
        )

        subprocess.run(
            [   "powershell", "-Command",
                f" Get-NetIPAddress | Select InterfaceAlias, IPAddress, AddressFamily |"
                # f"Where - Object{{$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'}} |"
                # f"Select-Object InterfaceAlias, IPAddress | "
                f"Export-Csv '{self.path}\\5info.csv' -NoTypeInformation -Append"],shell=True
        )

        subprocess.run(
            ["powershell", "-Command",
             f"Get-MpComputerStatus | "
             f"Select AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected | Export-Csv '{self.path}\\4info.csv' -NoTypeInformation -Append "],
            shell=True)


        subprocess.run(
            ["powershell", "-Command",
             f"Get-NetFirewallProfile | Select Name, LogAllowed, LogBlocked, LogFileName | " 
             f"Export-Csv '{self.path}\\6info.csv' -NoTypeInformation -Append "],
            shell=True
        )

        # os info

        subprocess.run(
            ["powershell", "-Command",
             f" Get-ComputerInfo | Select OsName, OsVersion, OsBuildNumber | " 
             f"Export-Csv '{self.path}\\7info.csv' -NoTypeInformation -Append "],
            shell=True
        )

    def powershell_log(self):
        command = subprocess.run(["powershell", "-command",
                                  "Get-LocalUser | Where-Object{$_.Enabled -match $True} | Select-Object -ExpandProperty Name"],
                                 capture_output=True, text=True)
        self.pc_users.extend(command.stdout.splitlines())
        empty_list = []

        for i in self.pc_users:
            location = rf"C:\Users\{i}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

            if os.path.exists(location):
                location_2 = fr"{self.filtered_evidence}\\powershell_{i}.txt"
                shutil.copyfile(location, location_2)

                empty_list.append([i, location_2])

        csv_path = fr"{self.filtered_evidence}\powershell_history.csv"

        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["User", "File_Path"])  # Header
            writer.writerows(empty_list)

        print("\n [+] Basic Information collection scan completed", flush=True)