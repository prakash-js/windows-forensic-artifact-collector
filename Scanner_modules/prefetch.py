import csv
import subprocess
from datetime import date, timedelta, datetime
from dbs.hash_db import hashStoring
import os
from Scanner_modules.hashChecker import hash_checking
hs_f = hash_checking()
hs = hashStoring()
import sys


class prefetch_scan:

    def __init__(self, core_evidence, tools, final_evidence,no_of_days,hash_value): #hash_value = do hash checker want to run or not

        self.tool_location =  fr"{tools}\\"      #fr"forensic_tools\\WinPrefetchView.exe"
        self.no_of_days =int(no_of_days)
        self.report_evidence = rf"{final_evidence}\\pro_prefetch_evi.csv"              #final evi
        self.output_file1 = rf"{core_evidence}\lim_prefetch.csv"
        self.finalize = rf"{core_evidence}\\Limited_outputs.csv"
        self.output_core_dir = rf"{core_evidence}" #direct evidence
        self.key_value = hash_value


    # def run_prefetch_tool(self):
    #     a = f"{self.tool_location}WinPrefetchView.exe"
    #     print(a)
    #     subprocess.run(fr"{self.tool_location}WinPrefetchView.exe  /scomma {self.output_core_dir}\prefetch.csv")
    #
    #
    #     #
    #     # # if getattr(sys, 'frozen', False):
    #     # #     base_dir = sys._MEIPASS
    #     # # else:
    #     # #     base_dir = os.path.dirname(os.path.abspath(__file__))
    #     # #
    #     # # exe_path = os.path.join(base_dir, self.tool_location)
    #     # # output_csv = os.path.join(self.output_core_dir, "prefetch.csv")
    #     # #
    #     # # cmd = f'"{exe_path}" /scomma "{output_csv}"'
    #     # #
    #     # # subprocess.run(cmd, shell=True, check=True)
    #

    def run_prefetch_tool(self):
        exe_path = os.path.join(self.tool_location, "WinPrefetchView.exe")
        output_path = os.path.join(self.output_core_dir, "prefetch.csv")

        # Debug validation (optional but recommended)
        if not os.path.exists(exe_path):
            raise FileNotFoundError(f"Executable not found: {exe_path}")

        subprocess.run(
            [exe_path, "/scomma", output_path],
            check=True
        )

    def form_csv(self):
        with open(fr"{self.output_core_dir}\prefetch.csv", newline='', encoding='utf-8', errors='ignore') as infile, \
             open(self.output_file1, 'w', newline='', encoding='utf-8') as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            for row in reader:
                # safety check
                if len(row) < 8:
                    continue
                #A = row[0]              # Column A
                f = row[5]              # Column F
                #E = row[4]              # Column E
                h0 = row[7].split(',')[0].strip()   # Column H[0]

                writer.writerow([f.lower(),  h0.lower()])

    def refine_csv(self):
        # calculating days
        yesterday = date.today() - timedelta(days=self.no_of_days)


        # 🔹 CHANGE: use dict instead of list
        # key = path/exe, value = full row with latest runtime
        latest_rows = {}

        with open(self.output_file1, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)

            for row in reader:
                if not row:
                    continue

                path = row[0].strip()  # 🔹 CHANGE: path/exe column
                #
                # # last column: "DD-MM-YYYY HH:MM:SS"
                # date_part = row[-1].split(" ")[0]

                try:
                    row_datetime = datetime.strptime(row[-1], "%d-%m-%Y %H:%M:%S")
                except ValueError:
                    continue  # skip bad/header rows

                #  KEEP your original date filter
                if row_datetime.date() < yesterday:
                    continue

                # 🔹 CHANGE: dedup logic (keep latest runtime only)
                if path not in latest_rows:
                    latest_rows[path] = row
                else:
                    existing_time = datetime.strptime(
                        latest_rows[path][-1], "%d-%m-%Y %H:%M:%S"
                    )
                    if row_datetime > existing_time:
                        latest_rows[path] = row

            sorted_rows = sorted(
                latest_rows.values(),
                key=lambda r: datetime.strptime(r[-1], "%d-%m-%Y %H:%M:%S"),
                reverse=True
            )

        # 🔹 CHANGE: write only deduplicated + filtered rows
        with open(self.finalize, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(sorted_rows)


    def hash_checking(self):
        rows_kept = [["Exe_Path", "Date&Time" , "Signature","Threat Status"]]
        with open(self.finalize, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                if not row[0]:     #modified
                    continue        #modified

                value = row[0].strip()
                if row == "":
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
                execute = subprocess.run(["powershell","-NoProfile", "-Command", file_signature ],capture_output=True,text=True)
                row.append(execute.stdout.strip())



                hash_out = result.stdout.strip()
                verdict = hs_f.hash_checker(hash_out,self.key_value)
                if verdict == "whitelisted":
                    continue
                if verdict == "no specific threat":
                    continue
                row.append(verdict)
                rows_kept.append(row)

        with open(self.report_evidence, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_kept)

        print("[+] Prefetch artifacts scan completed\n", flush=True)



