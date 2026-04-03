import os
report_dict = {"report_sysinfo": 'sysinfo_report_template.html',
                    "self.report_prefetch": 'prefetch_report_template.py'}


def html_file(self):
    for i in report_dict:
        if not os.path.exists('sysinfo_report_template.html'):
            self.report_sysinfo = "not_found.html"
        else:
            pass


