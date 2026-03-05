import csv
import subprocess
from datetime import date, timedelta, datetime
from dbs.hash_db import hashStoring
from Scanner_modules.hashChecker import hash_checking
hs_f = hash_checking()
hs = hashStoring()


class live_process:

    def __init__(self, core_evidence, final_evidence,key_value):
        self.key_value = key_value
        self.report_evidence = rf"{final_evidence}\\pro_live_task_evi.csv"              #final evi
#        self.output_file1 = rf"{core_evidence}\lim_prefetch.csv"
        self.finalize = rf"{core_evidence}\all_process.csv"
        self.output_core_dir = rf"{core_evidence}" #direct evidence

    def run_get_process(self):
        cmd = cmd = fr"Get-Process | Select-Object Name, Id, Path | Export-Csv '{self.finalize}' -NoTypeInformation"
        subprocess.run(["powershell", "-command", cmd], capture_output=True, text=True)

    def hash_checking(self):
        rows_kept = [["File_Name", "Id", "File path" , "Signature" ,"Threat Status"]]
        with open(f"{self.finalize}", newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for idx , row in enumerate(reader):
                if not row:
                    continue
                if idx == 0:
                    continue

                value = row[2].strip()
                if not value:
                    continue

                cmd = (
                    f'Get-FileHash -Algorithm SHA256 -Path "{value}" '
                    '| Select-Object -ExpandProperty Hash'
                )

                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", cmd],
                    capture_output=True,
                    text=True
                )

                file_signature = fr"(Get-AuthenticodeSignature '{value}').Status"
                execute = subprocess.run(["powershell", "-NoProfile", "-Command", file_signature], capture_output=True,text=True)
                row.append(execute.stdout.strip())

                hash_out = result.stdout.strip()
                verdict = hs_f.hash_checker(hash_out, self.key_value)
                if verdict == "whitelisted":
                    continue
                if verdict == "no specific threat":
                    continue
                row.append(verdict)
                rows_kept.append(row)

                with open("unknown_hashes.txt", "a", encoding="utf-8") as f:
                    if hash_out.lower() not in hs.hash_dict:
                        f.write(str(hs.hash_dict) + "\n")
        with open(self.report_evidence, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_kept)

        print("[+] Running task artifacts scan completed\n", flush=True)


