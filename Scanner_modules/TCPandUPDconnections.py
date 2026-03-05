import subprocess
import csv
from dbs.hash_db import hashStoring
from Scanner_modules.hashChecker import hash_checking
hs_f = hash_checking()
hs = hashStoring()

class TCP_and_UDP:
    def __init__(self, core_evidence, real_evidence, key_value):
        self.TCP_Core = rf"{core_evidence}\\TCP_CORE.csv"
        self.TCP_Core_analysis = rf"{core_evidence}\\TCP_CORE_analysing.csv"


        self.TCP_filtered = rf"{real_evidence}\\TCP_With_path.csv"

        self.UDP_Core = rf"{core_evidence}\\UDP_CORE.csv"
        self.UDP_Core_analysis = rf"{core_evidence}\\UDP_CORE_analysing.csv"

        self.UDP_filtered = rf"{real_evidence}\\UDP_With_path.csv"

        self.api_value = key_value


    def TCP_Connections(self):
        cmd = (
                    "Get-NetTCPConnection | "
                    "Where-Object { "
                    "$_.State -in @('Established','SynSent','Listen') -and "
                    "$_.RemoteAddress -notin @('127.0.0.1','::1') -and "
                    "$_.LocalAddress -notin @('127.0.0.1','::1') -and"
                    "$_.RemoteAddress -notlike 'fe80::*' "
                    "} | "
                    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess, "
                    "@{Name='Conn_Type';Expression={'TCP'}} | "
                    f"Export-Csv '{self.TCP_Core}' -NoTypeInformation"
                )

        subprocess.run(["powershell", "-command" , cmd], capture_output=True, text=True )


    def adding_process_path_TCP(self):
        rows_kept = [["Local address","LocalPort","RemoteAddress","RemotePort", "State", "OwningProcess-ID", "Connection_type", "Execution_Path"]]
        with open(f"{self.TCP_Core}" , encoding="utf-8", newline="",errors="ignore") as file:
            reader = csv.reader(file)
            for idx, i in enumerate(reader):
                if idx == 0:
                    continue
                if not i:
                    continue
                process_id = i[5]
                cmd = f"Get-Process -Id {process_id} | Select-Object  -ExpandProperty Path"
                out_put = subprocess.run(["powershell", "-command", cmd],capture_output=True, text=True).stdout.strip()
                if not out_put:
                    continue
                i.append(out_put)
                rows_kept.append(i)

        with open(self.TCP_Core_analysis, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_kept)


    def UDP_connections(self):
        cmd = fr"""
                Get-NetUDPEndpoint |
                Where-Object {{
                    $_.LocalPort -ne 0 -and
                    $_.LocalAddress -notin @('127.0.0.1','::1') -and
                    $_.LocalAddress -notlike 'fe80::*' -and
                    $_.LocalAddress -ne '::'
                }} |
                Select-Object `
                    LocalAddress,
                    LocalPort,
                    OwningProcess,
                    @{{Name='Conn_Type';Expression={{ 'UDP' }} }} |
                    Export-Csv '{self.UDP_Core}' -NoTypeInformation 
                """

        subprocess.run(["powershell", "-command" , cmd], capture_output=True, text=True)

    def adding_process_path_UDP(self):
        rows_kept = [["LocalAddress", "LocalPort", "OwningProcess-ID", "Conn_Type","Execution_Path"]]
        with open(f"{self.UDP_Core}", encoding="utf-8", newline="", errors="ignore") as file:
            reader = csv.reader(file)
            for idx, i in enumerate(reader):
                if idx == 0:
                    continue
                if not i:
                    continue
                process_id = i[2]
                cmd = f"Get-Process -Id {process_id} | Select-Object  -ExpandProperty Path"
                out_put = subprocess.run(["powershell", "-command", cmd], capture_output=True, text=True).stdout.strip()
                if not out_put:
                    continue
                i.append(out_put)
                rows_kept.append(i)

        with open(self.UDP_Core_analysis, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_kept)


    def analysing_threat_level(self):
        check_files = [self.TCP_Core_analysis,self.UDP_Core_analysis]
        op_files = [self.TCP_filtered,self.UDP_filtered]

        for idx_file , i_file in enumerate(check_files):
            rows = []
            with open(check_files[idx_file], encoding="UTF-8",newline="" , errors="ignore") as file:
                reading = csv.reader(file)

                for idx,i in enumerate(reading):
                    if not i:
                        continue
                    if not i[0]:       #modified
                        continue       #modified
                    if idx == 0:
                        i.append("Threat Status")
                        rows.append(i)
                        continue
                    value = i[0].strip()

                    cmd = (
                        f'Get-FileHash -Algorithm SHA256 -Path "{value}" '
                        '| Select-Object -ExpandProperty Hash'
                    )

                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True,
                        text=True
                    ).stdout

                    hash_out = result.strip()
                    verdict = hs_f.hash_checker(hash_out,self.api_value)
                    if verdict == "whitelisted":
                        continue
                    if verdict == "no specific threat":
                        continue
                    i.append(verdict)
                    rows.append(i)

                with open(op_files[idx_file], "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerows(rows)

        print(" [+] Live Connection artifacts scan completed\n", flush=True)
