import os.path


class index_generator:

    def __init__(self,path,investigator):
        self.investigator = investigator
        self.html_path = f"{path}\\index.html"


    def html_writer(self):
        html = f"""
                <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Forensic Report</title>
        
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 30px;
                    background-color: #0a1a2f;   /* Navy blue */
                    color: #e6e6e6;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    background: #ffffff;
                    color: #000;
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
                a {{
                    color: #003366;
                    text-decoration: none;
                    font-weight: bold;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                iframe {{
                    width: 100%;
                    height: 770px;
                    border: 1px solid #444;
                    margin-top: 10px;
        
                    background: #fff;
                }}
                hr {{
                    border: 1px solid #334;
                }}
            </style>
        </head>
        
        <body>
        
        <h2>Windows Forensic Report</h2>
        <p>Report by <b>{self.investigator}</b></p>
        
        <hr>
        
        
        <table>
        
            <tr>
                <td><a href="#basic info" onclick="loadPage('sysinfo.html')">Windows Info</a></td>
                <td><a href="#prefetch" onclick="loadPage('prefetch_report.html')">Prefetch File</a></td>
                <td><a href="#services" onclick="loadPage('service_report.html')">Services </a></td>
                <td><a href="#startup" onclick="loadPage('startup_report.html')">Startup Folders</a></td>
            </tr>
            
            <tr>
                <td><a href="#LiveTasks" onclick="loadPage('registry_report.html')">registry</a></td>
                <td><a href="#networkconnection" onclick="loadPage('usb_final.html')"> USB artifacts</a></td>
                <td><a href="#firewall" onclick="loadPage('firewall_report.html')"> Firewall Artifacts</a></td>
                <td><a href="#Browser" onclick="loadPage('browser_artifacts.html','not_found.html')">Browser Artifacts</a></td>
            </tr>
            <tr>
                <td><a href="#LiveTasks" onclick="loadPage('live_conn.html','not_found.html')">Live Connections</a></td>
                <td><a href="#networkconnection" onclick="loadPage('live_task_report.html','not_found.html')">Live Task</a></td>
                <td><a href="#files" onclick="loadPage('dir_file_final.html')"> File Artifacts</a></td>
                <td><a href="#Browser" onclick="loadPage('win_def_report.html')">Windows defender  Artifacts</a></td>
                
            </tr>
            

            
        </table>
        
        
        <iframe id="contentFrame"></iframe>
        
        <script>
            function loadPage(page) {{
                document.getElementById("contentFrame").src = page;
            }}
        </script>
        
        </body>
        </html>
                """

        with open(self.html_path,'w',encoding="UTF-8", errors="ignore") as f:
            f.write(html)