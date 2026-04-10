import os
from datetime import date, timedelta, datetime
import subprocess
import csv
from Scanner_modules.hashChecker import hash_checking
hs_f = hash_checking()

class Scheduletask:
    def __init__(self, unproc_evi, finalize_evi, days, hash_value):
        self.key_value = hash_value
        self.unprocessed = unproc_evi
        self.processed = finalize_evi
        self.days = days


    def executing_command(self):


        cmd = fr'''
                Get-ScheduledTask | ForEach-Object{{
                $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath
                [PSCustomObject]@{{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                Executable = $_.Actions.Execute
                Class_id = $_.Actions.ClassId
                Last_run = $info.LastRunTime
                Next_run = $info.NextRunTime
                }}
                }} | Export-Csv "{self.unprocessed}\scheduled_process.csv" -NoTypeInformation -Append

                '''
        subprocess.run(['powershell', '-command', cmd] ,capture_output=True, text=True)


    def refining(self):
        preprocessed_list = [["TaskName", "TaskPath", "Executable", "Class_id", "Created_date", "Last_run", "Next_run", "Signature", "Threat-Status"],]
        with open(fr'{self.unprocessed}\\scheduled_process.csv','r') as schedule:
            reader = csv.reader(schedule)
            for i in reader:
                if not i[2]:
                    if i[3]:
                        cmd_check1 = fr'(Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\{i[3]}\InprocServer32")."(default)"'
                        cmd_check2 = fr'(Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\{i[3]}\LocalServer32")."(default)"'

                        try:
                            output1 = subprocess.run(['powershell', '-command', cmd_check1], capture_output=True, text=True,  timeout=3)
                            if output1.stdout:
                                path = output1.stdout
                                clean_path = os.path.expandvars(path.strip().strip('"').split(" ")[0])
                                i[2] = clean_path.strip()
                        except:
                            pass

                    try:
                        output2 = subprocess.run(['powershell', '-command', cmd_check2], capture_output=True, text=True, timeout=3)
                        if output2.stdout:
                            path = output2.stdout
                            clean_path = os.path.expandvars(path.strip().strip('"').split(" ")[0])
                            i[2] = clean_path.strip()
                    except:
                        pass


                if not i[2] or not os.path.exists(i[2]):
                    continue

                cmd_sub =f'(Get-ItemProperty "{i[2]}").LastWriteTime.ToString("dd-MM-yyyy HH:mm:ss")'
                try:
                    process_date = subprocess.run(['powershell', '-command', cmd_sub], capture_output=True, text=True,  timeout=3)
                except:
                    process_date = ""

                if not process_date.stdout:
                    process_date = "No date Found"
                    TaskName = i[0]
                    TaskPath = i[1]
                    Executable = i[2]
                    Class_id = i[3]
                    Created_date = process_date
                    Last_run = i[4]
                    Next_run = i[5]
                    signature = "Unverified"
                    hash_value = "undetected"

                    list1 = [TaskName, TaskPath, Executable, Class_id, Created_date, Last_run, Next_run, signature, hash_value]
                    preprocessed_list.append(list1)
                    continue

                test_date = datetime.today() - timedelta(days=self.days)
                filtering = datetime.strptime(process_date.stdout.strip(), "%d-%m-%Y %H:%M:%S")

                if test_date > filtering:
                    continue

                if os.path.exists(i[2]):
                    cmd_sign = fr"(Get-AuthenticodeSignature '{i[2]}').Status"

                    try:
                        sign = subprocess.run(['powershell', '-command', cmd_sign], capture_output=True, text=True)
                    except Exception as e:
                        pass

                    cmd_hash = (f'Get-FileHash -Algorithm SHA256 -Path "{i[2]}" '
                                '| Select-Object -ExpandProperty Hash'
                                )
                    try:
                        result = subprocess.run(["powershell", "-NoProfile", "-Command", cmd_hash], capture_output=True,text=True)
                    except Exception as e:
                        pass
                    verdict = hs_f.hash_checker(result.stdout.strip(), self.key_value)

                elif not os.path.exists(i[2]):
                    sign = "Unverified"
                    verdict = "undetected"

                TaskName = i[0]
                TaskPath = i[1]
                Executable = i[2]
                Class_id = i[3]
                Created_date = process_date.stdout.strip()
                Last_run = i[4]
                Next_run = i[5]
                signature = sign.stdout.strip()
                hash_value = verdict

                list1 = [TaskName, TaskPath, Executable, Class_id, Created_date, Last_run, Next_run,signature,hash_value]
                preprocessed_list.append(list1)


        with open(fr'{self.processed}\\proc_schedule.csv','a') as file1:
            writer = csv.writer(file1)
            writer.writerows(preprocessed_list)

        print(" [+] ScheduleTask artifacts scan completed", flush=True)



