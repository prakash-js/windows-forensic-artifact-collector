import csv
import os
import shutil

from dbs.SnippetStore_db import SnippetStore

db = SnippetStore()


class startups_op:

    def __init__(self, op_dir, op_csv):
        self.finalize = rf"{op_csv}"  # output_html
        self.output_html = f"{op_dir}\\startup_report.html"

    def html_writer(self):
        if not os.path.exists(self.finalize):
            try:
                shutil.copyfile("_internal/html_templates/not_found.html", self.output_html)
            except Exception as e:
                print(e)
            return

        with open(self.finalize, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Guard: empty CSV
        if not rows:
            raise ValueError("CSV file is empty")

        headers = rows[0]  # first row = header
        data_rows = rows[1:]  # rest = data

        html = f"""
        <!DOCTYPE html>
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

        <h2>{db.startup_db["Heading"]}</h2>

        <p>
            {db.startup_db["first_para"]}
        </p>

            <p>
            {db.startup_db["second_para"]}
        </p>

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
        </body>
        </html>
        """

        with open(self.output_html, "w", encoding="utf-8") as f:
            f.write(html)

        print("HTML report generated: Startup Folders  artifacts", flush=True)
