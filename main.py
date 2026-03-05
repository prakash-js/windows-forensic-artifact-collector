import os.path
import subprocess
import socket
import requests
import ctypes
import sys

## importing all modules of the Project

# from html_templates.sysinfo_report_template import First_module
from  dbs.api_checker import ApiConnectionHandler
from dbs.hash_db import hashStoring
from Scanner_modules.basic_sys_info import basic_system_info
from html_templates.index import index_generator
from html_templates.sysinfo_report_template import First_module
from Scanner_modules.prefetch import prefetch_scan
from  dbs.SnippetStore_db import SnippetStore
from html_templates.prefetch_report_template import prefetch_op
from Scanner_modules.persistence_check_module import services_artifacts
from html_templates.startup_file_report_template import startups_op
from html_templates.registry_template import reg_template
from html_templates.service_report_template import service_op
from Scanner_modules.live_tasks import live_process
from html_templates.live_taks_report import process_op
from Scanner_modules.TCPandUPDconnections import TCP_and_UDP
from Scanner_modules.hashChecker import hash_checking
from html_templates.live_connection_report_template import network_op
from Scanner_modules.firewall_artifacts import firewall_artifacts
from html_templates.firewall_report_template import firewall_op
from Scanner_modules.browser_artifacts import Browser_artifacts
from html_templates.browser_report_template import browser_op
from dbs.config_file import configuration_file
from Scanner_modules.dir_and_file_analyzer import dir_file_last_written
from html_templates.file_report_template import file_template

from Scanner_modules.windows_defender_artifacts import Windows_defender_artifacts
from html_templates.defender_artifacts import windows_defender

from Scanner_modules.USB_artifacts import USB_scan
from html_templates.usb_artifacts import usb_template


HA = configuration_file()
hash_storing = hashStoring()
db = SnippetStore()
ap = ApiConnectionHandler()


class Forensic_tool:

    def __init__(self):
        self.Investigator_name = None
        self.project_path = None
        self.cwd = os.popen("cd").read().strip()
        self.pre_tools_path = None
        self.real_evidence = None
        self.core_evidence = None
        self.save_hash = None
        self.sysinfo = None
        self.report_path = None
        self.conn_type = None
        self.no_of_days = None
        self.internet_conn = None
        self.api_value = None
        self.conn_count = None
        self.file_recursive = None


    def check_privilege(self):
        try:
            admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            admin = False

        if not admin:
            print("This tool must be run as Administrator.")
            sys.exit(1)

        return True

    def is_internet_available(self):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            self.internet_conn = True
        except OSError:
            self.internet_conn = False
            print("No Internet Connection")

    def checking_request(self,api):
        url = "https://www.hybrid-analysis.com/api/v2/key/current"
        headers = {
            "User-Agent": "Falcon",
            "api-key": f"{api}",
            "accept": "application/json"
        }
        print(f"The current API key that is present for Hybrid Analysis : {api}")
        try:
            response = requests.get(url, headers=headers,timeout=6)
        except Exception as HTTPSConnectionPool:
            print(HTTPSConnectionPool)
            return False

        if response.status_code == 200:
            self.api_value = True
            HA.api_key['api_key'] = api.strip()

        else:
            print("Error:", response.status_code, response.text)
            self.api_value = False
            self.checking_api()


    def checking_api(self):
        if self.internet_conn:
            api_key = HA.api_key.get('api_value')
            if not api_key:
                while True:
                    answer = input("There is no API key present. Do you want to add one? (Yes/No)")
                    if answer.lower() == "no":
                        print("See the README for instructions on adding the API key manually. File hash analysis is not performed in this scan.")
                        return False

                    if answer.lower() == "yes":
                        api_keys = input("Enter the API key :")
                        self.checking_request(api_keys)
                        break

            if api_key:
                self.checking_request(api_key.strip())

        else:
            self.api_value = False

    def tool_requirements(self):
        while True:
            self.Investigator_name = input("Enter the investigator’s name :")
            if self.Investigator_name:
                break

        while True:
            self.no_of_days = int(input("How many days back should the investigation begin? (e.g., 1) : "))
            if self.no_of_days >= 1:
                break
            else:
                print("Invalid input. Please select a value starting from 1 and enter a valid integer (e.g., 1, 2, 3) ")

        while True:
            self.conn_type = input("Choose which firewall logs to collect (TCP / UDP / Both): ").lower().strip()
            if self.conn_type == "tcp" or  self.conn_type == "udp" or self.conn_type == "both":
                break
            else:
                print("Invalid input. Please select one of the following: TCP, UDP, or Both.")
        ##
        while True:
            self.conn_count = int(
                input("What is the expected inbound and outbound connection count for each IP? (Enter 0 if unknown): ")
            )
            if self.conn_count >= 0:
                break
            else:
                print("Invalid input. Please select a value starting from 1 and enter a valid integer (e.g., 1, 2, 3 ...),If you are unsure of the expected count, use zero as the input.")
        ##
        while True:
            answer = input(
                "Do you want to continue the file analysis recursively? (yes or no): "
            ).strip().lower()

            if answer == "yes":
                self.file_recursive = True
                break
            elif answer == "no":
                self.file_recursive = False
                break
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")


        while True:
            answer = input("Do u want to save the recent hashes (yes or no) : ").lower()
            if answer == "yes":
                self.save_hash = True
                break
            if answer == "no":
                self.save_hash = False
                break
            else:
                print("Invalid input. Please select one of the following: yes or no.")



    def output_dir(self):
        while True:
            get_directory = input("Provide the output directory name : ").strip()

            if os.path.exists(f"{self.cwd}\\{get_directory}"):
                print("the project name is already exist")
            else:
                os.mkdir(f"{self.cwd}\\{get_directory}")
                self.project_path = f"{self.cwd}\\{get_directory}"
                break

        # FIX 2: create folders only AFTER project_path exists
        # os.mkdir(f"{self.project_path}\\forensic_tools")
        self.pre_tools_path = f"{self.cwd}\\_internal\\forensic_tools"   #######


        os.mkdir(f"{self.project_path}\\report")
        self.report_path = f"{self.project_path}\\report"



        # os.mkdir(f"{self.project_path}\\Limited_Evidence")
        # self.real_evidence = f"{self.project_path}\\Evidence"

        os.mkdir(f"{self.project_path}\\Core_evidence")
        self.core_evidence = f"{self.project_path}\\Core_evidence"

        os.mkdir(f"{self.project_path}\\processed_evidence")
        self.real_evidence = f"{self.project_path}\\processed_evidence"

        os.mkdir(f"{self.project_path}\\sysinfo")
        self.sysinfo = f"{self.project_path}\\sysinfo"


    def hash_printing_and_saving(self):

        all_hashes = hash_storing.hash_dict
        hash_storing.hash_dict = all_hashes
        print(all_hashes)


#----------calling Modules --------------------------------------------------------------------------------------------

forensic_run = Forensic_tool()
forensic_run.check_privilege()
forensic_run.is_internet_available()
forensic_run.checking_api()
forensic_run.output_dir()
forensic_run.tool_requirements()

#Sys
system_info = basic_system_info(forensic_run.sysinfo)
system_info.collecting_info()
First_module(forensic_run.sysinfo,forensic_run.report_path).html_method()

##Live Network Connection Artifacts && Report Section
TUC = TCP_and_UDP(forensic_run.core_evidence, forensic_run.real_evidence,forensic_run.api_value)
TUC.TCP_Connections()
TUC.adding_process_path_TCP()
TUC.UDP_connections()
TUC.adding_process_path_UDP()
TUC.analysing_threat_level()

##Generating Report
nc_path1 = f"{forensic_run.real_evidence}\\{db.TCP["csv_name"]}"
nc_path2 = f"{forensic_run.real_evidence}\\{db.UDP["csv_name"]}"
network_op(forensic_run.report_path,nc_path1,nc_path2).html_writer_f1()
#
#
##Analysing Firewall Log && Report Section
firewall_log = firewall_artifacts(forensic_run.core_evidence,forensic_run.real_evidence,forensic_run.no_of_days,forensic_run.conn_type,forensic_run.conn_count)
firewall_log.Logfile()
firewall_log.filtering_csv()
#
# ## Generating Report
fw_inbound_path = f"{forensic_run.real_evidence}\\{db.firewall_inbound["csv_name"]}"
fw_outbound_path = f"{forensic_run.real_evidence}\\{db.firewall_outbound["csv_name"]}"
firewall_op(forensic_run.report_path,fw_inbound_path,fw_outbound_path).html_writer_f1()
#
#
# ##Prefetch File Scanning && Report Section
ps = prefetch_scan(forensic_run.core_evidence,  forensic_run.pre_tools_path, forensic_run.real_evidence,1,forensic_run.api_value)
ps.run_prefetch_tool()
ps.form_csv()
ps.refine_csv()
ps.hash_checking()
# #
# ## Generating Report for Prefetch:
prefetch_path = f"{forensic_run.real_evidence}\\{db.pref_db["csv_name"]}"
prefetch_op(forensic_run.report_path, prefetch_path).html_writer()
# #
# #
# # ##System Persistence and Persistence Report Section
persistence_chk = services_artifacts(forensic_run.core_evidence, forensic_run.real_evidence, forensic_run.no_of_days,forensic_run.api_value)
persistence_chk.service_checking()          #service_checking
persistence_chk.analysing_csv()             #service_checking
persistence_chk.start_up_folder()           #startup_folder
persistence_chk.registry_artifacts()        #registry_checking
# #
# # ##Generating Report for Services:
service_path =  f"{forensic_run.real_evidence}\\{db.service_db["csv_name"]}"
service_op(forensic_run.report_path, service_path).html_writer()
# #
# # ##Generating Report for Startup Folders:
start_path =  f"{forensic_run.real_evidence}\\{db.startup_db["csv_name"]}"
startups_op(forensic_run.report_path, start_path).html_writer()
# #
# ##Generating Report for Registry scan:
reg_path =  f"{forensic_run.real_evidence}\\{db.registry["csv_name"]}"
reg_template(forensic_run.report_path, reg_path).html_writer()
# #
# #
#Live Process analysing && Report Section
live_process_module =  live_process(forensic_run.core_evidence, forensic_run.real_evidence, forensic_run.api_value)     #live (taskmanager)
live_process_module.run_get_process()
live_process_module.hash_checking()

#Generating Report
lp_path = f"{forensic_run.real_evidence}\\{db.live_task_db["csv_name"]}"
process_op(forensic_run.report_path,lp_path).html_writer()
# #
# #
# ##Browser history analysing && Report Section
browser_art = Browser_artifacts(forensic_run.no_of_days,forensic_run.core_evidence,forensic_run.real_evidence)
browser_art.collecting_users()
browser_art.edge_data()
browser_art.firefox_artifacts()
browser_art.chrome_artifacts()
#
##Generating Report
browser_path = f"{forensic_run.real_evidence}\\{db.browser["csv_name"]}"
browser_op(forensic_run.report_path,browser_path).html_writer()
# #
#
# ##File Generator
dr_files = dir_file_last_written(forensic_run.no_of_days,forensic_run.real_evidence,forensic_run.file_recursive)
dr_files.checking_dir()
# ##Generating report
#
dr_path  = f"{forensic_run.real_evidence}\\{db.file["csv_name"]}"
file_template(forensic_run.report_path,dr_path).html_writer()


##windows defender
win_def = Windows_defender_artifacts(forensic_run.no_of_days,forensic_run.real_evidence)
win_def.windows_def_turned_off()
win_def.quarantined_files()

##Generating Report
wd_path  = f"{forensic_run.real_evidence}\\{db.win_def["csv_name"]}"
rt_path = f"{forensic_run.real_evidence}\\{db.real_time["csv_name"]}"
windows_defender(forensic_run.report_path,wd_path,rt_path).html_writer_f1()
#

##USB artifacts
usb = USB_scan(forensic_run.core_evidence,forensic_run.pre_tools_path,forensic_run.real_evidence,forensic_run.no_of_days)
usb.run_USB_tool()
usb.form_csv()
usb.refine_csv()

##Generate Report
usb_path  = f"{forensic_run.real_evidence}\\{db.USB["csv_name"]}"
usb_template(forensic_run.report_path,usb_path).html_writer()


index_generator(forensic_run.report_path,forensic_run.Investigator_name).html_writer()

if forensic_run.save_hash:
    forensic_run.hash_printing_and_saving()
if not forensic_run.save_hash:
    print("Scan Completed Perfectly")
