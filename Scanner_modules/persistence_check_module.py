import os.path
import subprocess
import csv
import re
from Scanner_modules.hashChecker import hash_checking
from dbs.hash_db import hashStoring

hs_f = hash_checking()
hs = hashStoring()

class services_artifacts:

    def __init__(self, save_path,final_path,date,key_value):
        self.date = date
        self.unfiltered_artifacts = save_path       #unprocessed
        self.filtered_artifacts = final_path
        self.key_value = key_value

# service_checking
    def service_checking(self):
        ps_command = rf"""
            Get-WinEvent -FilterHashtable @{{
                LogName = "System"
                Id = 7045
                StartTime = (Get-Date).AddDays(-{self.date})
            }} | ForEach-Object {{
                if ($_.Message -match 'Service File Name:\s*"([^"]+\.exe)[\s\S]*?Service Start Type:\s*(.+)')  {{
                    [PSCustomObject]@{{
                        TimeCreated = $_.TimeCreated
                        ImagePath  = $Matches[1]
                        Start_Type = $Matches[2]
                    }}
                }}
            }} | Export-Csv '{self.unfiltered_artifacts}\\services.csv' -NoTypeInformation -Append
            """


        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True
        )

    def analysing_csv(self):
        if not os.path.exists(fr"{self.unfiltered_artifacts}\\services.csv"):
            return
        rows_kept = [["TimeCreated","ImagePath", "start_type", "Signature" , "Threat_status"],]
        try:
            with open(f'{self.unfiltered_artifacts}\\services.csv', encoding='UTF8' , errors='ignore', newline="") as f:

                csv_reader = csv.reader(f)
                for idx , i in enumerate(csv_reader):

                    if not i:
                        continue
                    if idx == 0:
                        continue

                    row = i[1]


                    cmd = (
                        f'Get-FileHash -Algorithm SHA256 -Path "{row}" '
                        '| Select-Object -ExpandProperty Hash'
                    )

                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True,
                        text=True
                    )

                    file_signature = fr"(Get-AuthenticodeSignature '{row}').Status"
                    execute = subprocess.run(["powershell", "-NoProfile", "-Command", file_signature],
                                             capture_output=True, text=True)
                    i.append(execute.stdout.strip())

                    hash_out = result.stdout.strip()

                    verdict = hs_f.hash_checker(hash_out, self.key_value)
                    i.append(verdict)
                    rows_kept.append(i)
        except Exception as e:
            print(e)

        if len(rows_kept) > 1:
            with open(f"{self.filtered_artifacts}\\proc_srv.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows_kept)
        else:
            pass


        print("[ + ] Services artifacts scan completed\n")



#Startup folders

    def start_up_folder(self):
        system_startup = r"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"

        cmd =  fr""" $since = (Get-Date).AddDays(-{self.date})
                     $items = Get-ChildItem "{system_startup}" -Force |
                     Where-Object {{ $_.LastWriteTime -ge $since }} |
                     Select-Object Name, FullName, LastWriteTime,@{{ Name = 'User'; Expression = {{ 'system' }} }}
                     if ($items) {{
                        $items | Export-Csv "{self.unfiltered_artifacts}\\startups.csv" -NoTypeInformation -Append }}
                 """

        subprocess.run( ["powershell", "-Command", cmd,],text=True,capture_output=True )



        pc_users = []
        command = subprocess.run(["powershell", "-command","Get-LocalUser | Where-Object{$_.Enabled -match $True} | Select-Object -ExpandProperty Name"],capture_output=True, text=True)
        pc_users.extend(command.stdout.splitlines())

        for user in pc_users:
            cmd2 = fr"""
            $since = (Get-Date).AddDays(-{self.date})

            $items = Get-ChildItem "C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Force |
                Where-Object {{ $_.LastWriteTime -ge $since }} |
                Select-Object Name,
                              FullName,
                              LastWriteTime,
                              @{{ Name = 'User'; Expression = {{ '{user}' }} }}

            if ($items) {{
                $items | Export-Csv "{self.unfiltered_artifacts}\\startups.csv" -NoTypeInformation -Append
            }}
            """
            subprocess.run(["powershell", "-command", cmd2], capture_output=True, text=True)

            try:
                with open(f"{self.unfiltered_artifacts}\\startups.csv", encoding="UTF-8", newline="", errors='ignore')as file:


                    row_kept =[["Name","FullName","LastWriteTime" ,"user", "Signature" ,"Threat_status"]]
                    csv_file = csv.reader(file)
                    for idx, i in enumerate(csv_file):          #i-variable referred as each row

                        if not i:
                            continue
                        if idx == 0:
                            continue

                        row = i[1]

                        cmd = (
                            f'Get-FileHash -Algorithm SHA256 -Path "{row}" '
                            '| Select-Object -ExpandProperty Hash'
                        )

                        result = subprocess.run(
                            ["powershell", "-NoProfile", "-Command", cmd],
                            capture_output=True,
                            text=True
                        )

                        file_signature = fr"(Get-AuthenticodeSignature '{row}').Status"
                        execute = subprocess.run(["powershell", "-NoProfile", "-Command", file_signature],
                                                 capture_output=True, text=True)
                        i.append(execute.stdout.strip())


                        hash_out = result.stdout.strip()
                        verdict = hs_f.hash_checker(hash_out,self.key_value)
                        # if verdict == "whitelisted":
                        #     continue
                        # if verdict == "no specific threat":
                        #     continue
                        i.append(verdict)
                        row_kept.append(i)

                    try:

                        with open(f"{self.filtered_artifacts}\\startups.csv", "w", newline="", encoding="utf-8") as f:
                            writer = csv.writer(f)
                            writer.writerows(row_kept)
                    except Exception as e:
                        pass

            except Exception as e:
                pass


        print("[ + ] Startup Folders  artifacts scan completed \n")

#registry checking

    def registry_artifacts(self):
        empty_row = [["Name", "Path", "Key", "Signature", "Threat Status"]]

        list_run = [
            r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\\",
            r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\\"
        ]

        user_sids = subprocess.run(["powershell", "-command",
                                    "Get-LocalUser | Get-LocalUser | Where-Object { $_.Enabled } |Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value"],
                                   text=True, capture_output=True)
        a = user_sids.stdout.splitlines()
        for i in a:
            list_run.append(rf"Registry::HKEY_USERS\{i}\Software\Microsoft\Windows\CurrentVersion\RunOnce\\")
            list_run.append(rf"Registry::HKEY_USERS\{i}\Software\Microsoft\Windows\CurrentVersion\Run\\")

        for i in list_run:
            cmd = rf'''
                 (Get-ItemProperty "{i}").PSObject.Properties |
                Where-Object {{ $_.Name -notlike 'PS*' }} |
                ForEach-Object {{
                        [PSCustomObject]@{{
                        Name = $_.Name
                        Path = $_.Value
                        Key  = "{i}"
                    }}
                }} | Export-Csv "{self.unfiltered_artifacts}\\registry.csv" -NoTypeInformation  -Append

                    '''


            subprocess.run(["powershell", "-command", cmd], capture_output=True, text=True)




        try:
            with open(f'{self.unfiltered_artifacts}\\registry.csv', 'r', newline="", errors="ignore") as file:
                csv_reading = csv.reader(file)
                for idx, i in enumerate(csv_reading):
                    if idx == 0:
                        continue
                    value = i[1].strip()
                    m = re.search(r'"?(.*?\.exe)"?', value, re.IGNORECASE)
                    if not m:
                        continue
                    exe_path = m.group(1)

                    file_signature = fr"(Get-AuthenticodeSignature '{exe_path}').Status"
                    execute = subprocess.run(["powershell", "-NoProfile", "-Command", file_signature], capture_output=True,
                                             text=True)

                    a = i[0]
                    b = exe_path
                    c = i[2]
                    d = execute.stdout.strip()
                    row_kept = ([a, b, c, d])

                    cmd = (
                        f'Get-FileHash -Algorithm SHA256 -Path "{value}" '
                        '| Select-Object -ExpandProperty Hash'
                    )

                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True,
                        text=True
                    )

                    hash_out = result.stdout.strip()
                    verdict = hs_f.hash_checker(hash_out,self.key_value)
                    row_kept.append(verdict)
                    empty_row.append(row_kept)

        except Exception as e:
            pass

        try:
            with open(f'{self.filtered_artifacts}\\finalize_registry.csv', 'a', newline="", errors="ignore") as file2:
                for items in empty_row:
                    csv_writer = csv.writer(file2)
                    csv_writer.writerow(items)

            print("[+] Registry artifacts scan completed\n", flush=True)

        except Exception as e:
            pass











