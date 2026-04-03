import os
import csv
from app_data.SnippetStore_db import SnippetStore

db = SnippetStore()
# FT = Forensic_tool()

class First_module:
    def __init__(self, mainpath, report,filtered_evidence):

        self.main_path = mainpath
        self.output_html = f"{report}\\sysinfo.html"
        self.csv_file = fr"{filtered_evidence}\powershell_history.csv"



    def html_method(self):
        html = f"""        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>Forensic Pipeline Report</title>
        <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
        }}
        th, td {{
            border: 1px solid #444;
            padding: 6px;
            text-align: left;
        }}
        th {{
            background: #222;
            color: #fff;
        }}
        tr:nth-child(even) {{
            background: #f2f2f2;
        }}
        </style>
        </head>
        <body>
    
        <h2>{db.db_dict["Heading"]}</h2>
    
        <p style="font-size: 20px; line-height: 1.8; color: black;">
        This section focuses on general system information. It provides an overview of the system configuration and environment at the time of analysis.
        </p>"""


        for i in range(1, 8):
            path = fr"{self.main_path}\{i}info.csv"

            if os.path.exists(path):
                with open(path, newline='', encoding="UTF-8", errors="ignore") as file:
                    reader = csv.reader(file)
                    row = list(reader)

                headers = row[0]        # first row = header
                data_rows = row[1:]     # rest = data

                html += rf"""<br>
                
        <h2>{db.db_dict[f'user_title{i}']}</h2>
    
        <table>
        <tr>
            {''.join(f'<th>{h}</th>' for h in headers)}
        </tr>
        """

                for row in data_rows:
                    html += "<tr>"
                    for cell in row:
                        html += f"<td>{cell}</td>"
                    html += "</tr>"

                html += """
        </table>
    
        """
            else:
                continue

        # if os.path.exists("processed_evidence/powershell_log.txt"):
            #
            # html += """
            #             <hr>
            #             <p>
            #             The PowerShell log records command execution activity within the system during the selected investigation.
            #             Analyzing this log helps identify potentially suspicious or unauthorized PowerShell commands, scripts, or automated
            #             tasks that may indicate malicious activity, lateral movement, or persistence mechanisms.
            #             </p>
            #
            #             <a href="powershell_log.txt" target="_blank" style="text-decoration:none;">
            #                 <button type="button">Show PowerShell Log</button>
            #             </a>"""
            #

        html += fr"""
        <br>
        <br>
        <h2>{db.powershell_log["Heading"]}</h2>
        <p>{db.powershell_log["first_para"]}</p>
        

        <table>
        <tr>
        <th>Username</th>
        <th>Powershell Log</th>
        </tr>
        """

        with open(self.csv_file, newline='') as f:
            reader = csv.DictReader(f)

            for row in reader:
                user = row["User"]
                path = row["File_Path"]

                html += f"""
        <tr>
        <td>{user}</td>
        <td><a href="file:///{path}" target="_blank">Open Log</a></td>
        </tr>
        """

        html += "</table>"




        html += """<br><hr><br>
        </body>
        </html>
        """


        with open(self.output_html, "w", encoding="utf-8") as f:
            f.write(html)

        print(" HTML report generated : Basic System Scan\n", flush=True)

