import subprocess
from datetime import datetime, timedelta, date
import sqlite3
import csv
import shutil
import os


class Browser_artifacts:

    def __init__(self, days_back,unfiltered_path, filtered_path):
        self.days_back = days_back
        self.pc_users = []
        self.artifacts_date = None
        self.unfiltered_evidence = unfiltered_path
        self.filtered_evidence = rf"{filtered_path}\\browser_artifacts.csv"


    def collecting_users(self):
        command = subprocess.run(["powershell", "-command",
                                  "Get-LocalUser | Where-Object{$_.Enabled -match $True} | Select-Object -ExpandProperty Name"],
                                 capture_output=True, text=True)
        self.pc_users.extend(command.stdout.splitlines())

        calculating_dates = datetime.today() - timedelta(days=self.days_back)
        self.artifacts_date = calculating_dates.date()


    def edge_data(self):
        edge_artifacts = [["Downloaded URL", "Destination file Location", "Date", "Browser", "User"]]

        # Information from Edge
        for i in self.pc_users:
            edge_dir = fr"C:\Users\{i}\AppData\Local\Microsoft\Edge\User Data\Default\History"
            if not os.path.exists(edge_dir):
                continue

            connection = sqlite3.connect(edge_dir)
            cursor = connection.cursor()

            contents = cursor.execute("""SELECT tab_url,target_path,datetime(start_time / 1000000 - 11644473600, 'unixepoch') AS start_time_utc FROM downloads;""") # datetime(end_time / 1000000 - 11644473600, 'unixepoch') AS end_time_utc, current_path

            for row in contents:
                row = list(row)
                date_time = str(row[2]).split(' ')
                splitted_date = date_time[0]
                real = splitted_date[0:]
                row_date = datetime.strptime(real, "%Y-%m-%d").date()
                if row_date >= self.artifacts_date:
                    row.append("Edge")
                    row.append(i)
                    edge_artifacts.append(row)

        try:
            with open(self.filtered_evidence, 'a', newline="", errors="ignore") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerows(edge_artifacts)
        except Exception as e:
            pass


    def firefox_artifacts(self):
        firefox_datas = []
        user_dict = {}
        if not os.path.exists(self.filtered_evidence):
            firefox_datas.append(["Downloaded URL", "Destination file Location","Date", "Browser"])

        set_fire_profile = set()
        for i in self.pc_users:
            dir_to_check = fr"C:\Users\{i}\AppData\Roaming\Mozilla\Firefox\Profiles\\"
            cmd = fr'''
                    Get-ChildItem "{dir_to_check}" -Recurse -File |
                    Where-Object {{ $_.Name -eq 'places.sqlite' }} |
                    Select-Object -First 1 -ExpandProperty FullName
                    '''

            output = subprocess.run(["powershell", "-command", cmd], capture_output=True,text=True)
            output_splitted = output.stdout.splitlines()
            for users in output_splitted:
                user_dict[users] = i

                set_fire_profile.add(users)



        for sql_file in set_fire_profile:
            if not os.path.exists(sql_file):
                continue

            conn = sqlite3.connect(sql_file)
            cursor = conn.cursor()

            # cursor.execute("PRAGMA table_info(moz_annos);")
            query = ''' SELECT p.url AS source_url, REPLACE(a.content,'file:///', '') AS destination_path, datetime(a.dateAdded/1000000,'unixepoch') AS annotation_time FROM moz_annos a
                        JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
                        JOIN moz_places p ON a.place_id = p.id
                        WHERE aa.name = 'downloads/destinationFileURI' ;
                    '''

            cursor.execute(query)
            table_inside = cursor.fetchall()



            for index , row in enumerate(table_inside):
                row = list(row)
                date_time = str(row[2]).split(' ')
                splitted_date = date_time[0]
                row_date = datetime.strptime(splitted_date, "%Y-%m-%d").date()
                if row_date >=  self.artifacts_date:
                    row.append("Firefox")  #tuple won't append
                    row.append(user_dict.get(sql_file))
                    firefox_datas.append(row)

            conn.close()

        try:
            with open(self.filtered_evidence, 'a', newline="", errors="ignore") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerows(firefox_datas)
        except Exception as e:
            pass



    def chrome_artifacts(self):
        chrome_datas = []
        if not os.path.exists(self.filtered_evidence):
            chrome_datas.append(["Downloaded URL", "Destination file Location", "Browser", "User"])
        for i in self.pc_users:
            chrome_dir = fr"C:\Users\{i}\AppData\Local\Google\Chrome\User Data\Default\History"
            if not os.path.exists(chrome_dir):
                continue
            sql_connect = sqlite3.connect(chrome_dir)
            cluster = sql_connect.cursor()
            # content = cluster.execute("""
            # SELECT
            #     target_path,
            #     tab_url,
            #     datetime(start_time / 1000000 - 11644473600, 'unixepoch') AS start_time_utc
            # FROM downloads
            # """)
            content = cluster.execute("SELECT tab_url,target_path,datetime(start_time / 1000000 - 11644473600, 'unixepoch') FROM downloads")


            for row in content:
                date_time = str(row[2]).split(' ')
                row = list(row)
                splitted_date = date_time[0]
                row_date = datetime.strptime(splitted_date, "%Y-%m-%d").date()
                if row_date >= self.artifacts_date:
                    row.append("Chrome")
                    row.append(i)
                    chrome_datas.append(row)


        try:
            with open(self.filtered_evidence, 'a', newline="", errors="ignore") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerows(chrome_datas)
        except Exception as e:
            pass

        print(" [+] Browser Artifacts collection scan completed", flush=True)



