from dbs.config_file import configuration_file
dir_files = configuration_file()
import subprocess
class dir_file_last_written:
    def __init__(self,back_days,fil_evi,recursive):
        self.back_days = back_days
        self.filtered_artifacts = fil_evi
        self.recursive = recursive
        self.file = dir_files.directory_config['directories']

    def checking_dir(self):
        #_internal
        # with (open('config_files/directory_configuration.txt','r') as file):
        for file_path in self.file:
            if not file_path:
                return

            if self.recursive:

                cmd = fr"""
                    $since = (Get-Date).AddDays(-{self.back_days})
                    $event = Get-ChildItem -Path "{file_path}" -Recurse -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.LastWriteTime -gt $since }} 
                    if ($null -ne $event) {{
                    $event | Select-Object Directory, Name, LastWriteTime |
                    Export-Csv "{self.filtered_artifacts}\dir_file.csv" -NoTypeInformation -Append
                    }}
                """
                subprocess.run(['powershell', '-command', cmd], text=True, capture_output=True)


            if not self.recursive:
                cmd = fr"""
                    $since = (Get-Date).AddDays(-{self.back_days})
                    $event = Get-ChildItem -Path "{file_path}" -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.LastWriteTime -gt $since }} 
                    if ($null -ne $event) {{
                    $event | Select-Object Directory, Name, LastWriteTime |
                    Export-Csv "{self.filtered_artifacts}\dir_file.csv" -NoTypeInformation -Append
                    }}
                """
                subprocess.run(['powershell', '-command', cmd], text=True, capture_output=True)

        print(" [+] Files Information scan completed", flush=True)