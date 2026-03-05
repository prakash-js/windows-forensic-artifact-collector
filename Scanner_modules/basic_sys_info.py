import subprocess

class basic_system_info:
    def __init__(self,path):
        self.path = path

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


        print(" [+] Basic Information collection scan completed", flush=True)