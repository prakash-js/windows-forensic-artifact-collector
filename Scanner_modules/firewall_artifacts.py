import os.path
import subprocess
import csv
from datetime import date, timedelta, datetime,date
from dbs.config_file import configuration_file
import os

whitelisted_ip = configuration_file()

class firewall_artifacts:

    def __init__(self,core_evidence_path, real_evidence_path,days,connection_type,conn_count):

        self.provided_date = f"date.today() - timedelta(days={days})"
        self.whitelisted_ips = {'8.8.8.8', '127.0.0.1','8.8.4.4' , '1.1.1.1', '224.0.0.251', 'ff02::fb','::1','142.251.32.110'}
        # self.whitelisted_ips = whitelisted_ip.whitelisted_ips['ip_address']
        self.core_file_path_inbound = f"{core_evidence_path}\\raw_inbound_traffic.csv"
        self.core_file_path_outbound = f"{core_evidence_path}\\raw_outbound_traffic.csv"
        self.real_file_path_inbound = f"{real_evidence_path}\\inbound_traffic.csv"
        self.real_file_path_outbound = f"{real_evidence_path}\\outbound_traffic.csv"
        # self.http_connections = conn
        self.connection_type = connection_type
        self.given_count = conn_count



    def Logfile(self):

        cmd = '''Get-NetFirewallProfile  |
        ForEach-Object{
        if($_.LogAllowed -eq $true){
            [Environment]::ExpandEnvironmentVariables($_.LogFileName)
        }}
            '''


        empty_list = []


        executing = subprocess.run(["powershell", "-command", cmd],capture_output=True, text=True).stdout
        empty_list.append(executing.splitlines())
        set_list = set(empty_list[0])
        if not set_list:
            return

        empty_rows_out = [["DATE", "TIME", "SRC_IP", "DEST_IP", "DEST_PORT", "CONN_TYPE"]]
        empty_rows_in = [["DATE", "TIME", "SRC_IP", "DEST_IP", "DEST_PORT", "CONN_TYPE"]]


        for i in set_list:
            try:
                with open(i, "r", encoding="utf-8", errors="ignore") as log, \
                        open(self.core_file_path_outbound, "w", newline="", encoding="utf-8") as outbound ,\
                        open(self.core_file_path_inbound, "w", newline="", encoding="utf-8") as inbound:

                    for line in log:
                        if '#' in line:
                            continue
                        if line.strip() == "":
                            continue
                        each_line = line.strip().split(" ")

                        if each_line[2] == "DROP":
                            continue
                        if each_line[3] == 2:
                            continue

                        protocol  = each_line[3].strip().lower()
                        if self.connection_type == 'tcp':
                            if protocol == 'udp':
                                continue
                        if self.connection_type == 'udp':
                            if protocol == 'tcp':
                                continue



                        else:
                            pass

                        if each_line[-1] == "SEND":
                            dates = each_line[0].replace('\x00', '').strip()
                            row_datetime = datetime.strptime(dates, "%Y-%m-%d").date()
                            provided_date = date.today() - timedelta(days=1)
                            if row_datetime < provided_date:
                                continue
                            else:
                                pass

                            time = each_line[1]
                            src_ip = each_line[4]

                            dest_ip  = each_line[5]
                            if dest_ip in self.whitelisted_ips:
                                continue
                            dest_port = each_line[7]
                            if dest_port == '1900':
                                continue
                            conn_type = each_line[3]
                            if conn_type == "ICMP":
                                continue
                            # if self.http_connections is True:
                            #     if dest_port == '443' or dest_port == '80':
                            #         continue

                            empty_rows_out.append([dates, time, src_ip, dest_ip, dest_port, conn_type])

                        if each_line[-1] == "RECEIVE":
                            dates = each_line[0].replace('\x00', '').strip()
                            row_datetime = datetime.strptime(dates, "%Y-%m-%d").date()
                            provided_date = date.today() - timedelta(days=1)
                            if row_datetime < provided_date:
                                continue
                            else:
                                pass

                            time = each_line[1]
                            source_ip = each_line[4]
                            conn_type = each_line[3]
                            dest_ip = each_line[5]
                            source_port = each_line[7]
                            dest_port = each_line[7]

                            if dest_ip in self.whitelisted_ips:
                                continue
                            # if source_port in self.whitelisted_ips:
                            #     continue


                            if dest_port == '1900':
                                continue
                            if conn_type == "ICMP":
                                continue
                            if conn_type == 2 or  conn_type == "2":
                                continue

                            empty_rows_in.append([dates, time ,source_ip ,dest_ip, dest_port,conn_type])


                    if not empty_rows_in:
                        pass
                    else:
                        writing1 = csv.writer(inbound)
                        writing1.writerows(empty_rows_in)

                    if not empty_rows_out:
                        pass
                    else:
                        writing2 = csv.writer(outbound)
                        writing2.writerows(empty_rows_out)
            except Exception as e:
                pass


    def filtering_csv(self):
        core_evidence_list = [self.core_file_path_inbound,self.core_file_path_outbound]
        real_evidence_list = [self.real_file_path_inbound,self.real_file_path_outbound]

        for idx , i in enumerate(core_evidence_list):


            if not os.path.exists(core_evidence_list[idx]):
                print("Firewall log is disabled on this System No firewall logs")
                continue
            try:
                with open(core_evidence_list[idx], "r", newline="", encoding="utf-8") as file_1:
                    reading = csv.reader(file_1)
                    organized = {}
                    for idxing , row in enumerate(reading):
                        if idxing == 0:
                            continue
                        dates, time = row[0], row[1]
                        src_ip = row[2]
                        dst_ip = row[3]
                        dst_port = row[4]
                        protocol = row[-1]

                        if dst_port == '-':
                            continue

                        key = (src_ip, dst_ip, dst_port)

                        if key in organized:
                            organized[key]["count"] += 1
                            organized[key]["last_seen"] = (dates, time)
                            organized[key]["PROTOCOLS"].add(protocol)
                        else:
                            organized[key] = {
                                "first_seen": (dates, time),
                                "last_seen": (dates, time),
                                "count": 1,
                                "PROTOCOLS": {protocol},
                            }

                    empty_list_incoming = [['First_seen', 'Last_Seen', 'Source_ip', 'Destination_ip', 'Destination_port', "Conn_count" , "PROTOCOL" ]]
                    for (src, dst, dport), data in organized.items():
                        fs = f"{data['first_seen'][0]} {data['first_seen'][1]}"
                        ls = f"{data['last_seen'][0]} {data['last_seen'][1]}"
                        if data['count'] < self.given_count:
                            continue

                        empty_list_incoming.append([
                            fs,
                            ls,
                            src,
                            dst,
                            dport,
                            data['count'],
                            ", ".join(sorted(data['PROTOCOLS']))  # clean CSV value
                        ])
            except Exception as e:
                pass

            try:
                with open(real_evidence_list[idx], "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerows(empty_list_incoming)
                    f.close()
                file_1.close()
            except Exception as e:
                pass
        print("[+] Firewall artifacts scan completed\n", flush=True)





