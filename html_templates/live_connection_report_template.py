import csv
import os.path
import shutil

from dbs.SnippetStore_db import SnippetStore
db = SnippetStore()


class network_op:

    def __init__(self, op_dir, op_csv_tcp, op_csv_udp):
        self.output_html = f"{op_dir}\\live_conn.html"

        self.TCP = rf"{op_csv_tcp}"  # output_html
        self.UDP = op_csv_udp
        self.html = """
                <!DOCTYPE html>
                <html>
                <head>
                <meta charset="utf-8">
                <title>Forensic Pipeline Report</title>
                <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 30px;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                }
                th, td {
                    border: 1px solid #444;
                    padding: 6px;
                    text-align: left;
                }
                th {
                    background: #222;
                    color: #fff;
                }
                tr:nth-child(even) {
                    background: #f2f2f2;
                }
                </style>
                </head>
                <body>
                """

    def html_writer_f1(self):

        # Case: both missing
        if not os.path.exists(self.TCP) and not os.path.exists(self.UDP):
            try:
                with open(self.output_html, "w", encoding="utf-8") as f, \
                        open("_internal/html_templates\not_found.html", "r", encoding="utf-8") as f2:
                    f.write(f2.read())
                print(self.output_html)
                return
            except Exception:
                return

        # WD missing
        if not os.path.exists(self.TCP):
            self.html += """
            <h2 style="color:#555; font-family: Arial, sans-serif; margin-top:20px;">
                No Related Artifacts Were Identified on This System
            </h2>
            """
        else:
            with open(self.TCP, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                rows = list(reader)

            if rows:
                headers = rows[0]
                data_rows = rows[1:]

                self.html += fr"""
                <h1>{db.TCP["Heading"]}</h2>
                <h2>{db.TCP["Title"]}</h2>
                <p>
                    {db.TCP["first_para"]}
                </p>

                    <p>
                    {db.TCP["second_para"]}
                </p>

                <table>
                <tr>
                    {''.join(f'<th>{h}</th>' for h in headers)}
                </tr>
                """

                for row in data_rows:
                    self.html += "<tr>"
                    for cell in row:
                        self.html += f"<td>{cell}</td>"
                    self.html += "</tr>"

                self.html += "</table> <br>"

        # RT section
        self.html_writer_f2()

        # Final write
        self.html += "</body></html>"
        self.writing_html()

#------------------------------------------------------------------------------------------------------------------------
    def html_writer_f2(self):

        if not os.path.exists(self.UDP):
            self.html += """
            <br>
            <hr>
            <br>
            <h2 style="color:#555; font-family: Arial, sans-serif; margin-top:20px;">
                No Related Artifacts Were Identified on This System
            </h2>
            """
            return
        else:

            with open(self.UDP, newline="", encoding="utf-8", errors="ignore") as f2:
                reader = csv.reader(f2)
                rows = list(reader)

            if not rows:
                return

            headers = rows[0]
            data_rows = rows[1:]

            self.html += f"""
            <h2>{db.UDP["Title"]}</h2>

            <p>
                {db.UDP["first_para"]}
            </p>

                <p>
                {db.UDP["second_para"]}
            </p>

            <table>
            <tr>
                {''.join(f'<th>{h}</th>' for h in headers)}
            </tr>
            """

            for row in data_rows:
                self.html += "<tr>"
                for cell in row:
                    self.html += f"<td>{cell}</td>"
                self.html += "</tr>"

            self.html += "</table> <br>"

    def writing_html(self):
        with open(self.output_html, "w", encoding="utf-8") as f:
            f.write(self.html)
            print("HTML report generated: Live Network Connections")