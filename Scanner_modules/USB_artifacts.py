import csv
import subprocess
from datetime import date, timedelta, datetime
import os


class USB_scan:

    def __init__(self, core_evidence, tools, final_evidence,no_of_days):

        self.tool_location =  fr"{tools}\\"      #fr"forensic_tools\\WinPrefetchView.exe"
        self.no_of_days =int(no_of_days)
        self.report_evidence = rf"{final_evidence}\\pro_USB_evi.csv"              #final evi
        self.output_file1 = rf"{core_evidence}\lim_USB.csv"
        self.finalize = rf"{core_evidence}\\Limited_outputs.csv"
        self.output_core_dir = rf"{core_evidence}" #direct evidence

    def run_USB_tool(self):
        exe_path = os.path.join(self.tool_location, "USBDriveLog.exe")
        output_path = os.path.join(self.output_core_dir, "USB.csv")

        # Debug validation (optional but recommended)
        if not os.path.exists(exe_path):
            raise FileNotFoundError(f"Executable not found: {exe_path}")

        subprocess.run(
            [exe_path, "/scomma", output_path],
            check=True
        )

    def form_csv(self):
        with open(fr"{self.output_core_dir}\USB.csv", newline='', encoding='utf-8', errors='ignore') as infile, \
             open(self.output_file1, 'w', newline='', encoding='utf-8') as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            for row in reader:

                A = row[0]              # Column A
                B = row[2]              # Column F
                C = row[4]
                V = row[5]
                E = row[6]
                F = row[8]

                writer.writerow([A.lower(),  B.lower(),C.lower(),V.lower(),E.lower(),F.lower()])

    def refine_csv(self):
        # calculating days
        empty_row = [['device model','manufacturer','plug time','unplug time','device id','capacity']]
        yesterday = date.today() - timedelta(days=self.no_of_days)
        try:
            with open(self.output_file1, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for idx , row in enumerate(reader):
                    if not row:
                        continue
                    if idx == 0:
                        continue
                    date_row = row[2].split(' ')[0]
                    row_datetime = datetime.strptime(date_row, "%d-%m-%Y")
                    if row_datetime.date() > yesterday:
                        empty_row.append(row)
        except Exception as e:
            print(e)

        try:
            if len(empty_row) > 1:
                with open(self.report_evidence, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerows(empty_row)
        except Exception as e:
            pass

        print(" [+] USB Artifacts scan completed", flush=True)
