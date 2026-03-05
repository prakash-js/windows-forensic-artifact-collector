import  subprocess

class Windows_defender_artifacts:

    def __init__(self, far_days, save_file):
        self.far_days = far_days
        self.save_file = save_file

    def windows_def_turned_off(self):
        cmd = fr'''
            $since = (Get-Date).AddDays(-{self.far_days})
            $event = Get-WinEvent -FilterHashtable @{{
                LogName = "Microsoft-Windows-Windows Defender/Operational"
                Id      = 5001
                StartTime = $since
            }} -MaxEvents 1 -ErrorAction SilentlyContinue

            if ($null -eq $event) {{

            $event = Get-WinEvent -FilterHashtable @{{
                    LogName = "Microsoft-Windows-Windows Defender/Operational"
                    Id      = 5001
                }} -MaxEvents 1 -ErrorAction SilentlyContinue
            }}

            if ($null -ne $event) {{
                $event | Select-Object `
                    TimeCreated,
                    Id,
                    LevelDisplayName,
                    ProviderName,
                    Message |
                Export-Csv '{self.save_file}\windows_defender.csv' -NoTypeInformation -Append
                }}
            '''


        subprocess.run(["powershell", "-Command", cmd,],text=True,capture_output=True)


#Real Time Protection
    def quarantined_files(self):
        cmd = fr'''
        $event = Get-WinEvent -FilterHashtable @{{
        LogName = "Microsoft-Windows-Windows Defender/Operational"
        Id      = 1116,1117,1119,1120
        StartTime = (Get-Date).AddDays(-{self.far_days})
            }} | ForEach-Object {{

        $severity = $null
        $path     = $null
        # $Detection Source = $null
        $Category = $null
        $message = $null

        $lines = $_.Message -split "`n"

        foreach ($line in $lines) {{
        $message = $lines[0]

        $parts = $line -split ":", 2


        switch ($parts[0].Trim()) {{
            "Severity"    {{ $severity = $parts[1].Trim() }}
            "Path"        {{ $path     = $parts[1].Trim() }}
            "Category"    {{ $category = $parts[1].Trim() }}
        }}
        }}

        [PSCustomObject]@{{

        TimeCreated = $_.TimeCreated
        EventID     = $_.Id
        Severity    = $severity
        MalwarePath = $path
        Category = $Category
        Message = $message
        }}
        }}
        if ($null -ne $event) {{
        $event | Select-Object `
        TimeCreated,
        EventID,
        Severity,
        MalwarePath,
        Category,
        Message | Export-Csv '{self.save_file}\\realtime.csv' -NoTypeInformation -Append
        }}
        
        '''

        subprocess.run( ["powershell", "-Command", cmd,],text=True,capture_output=True )
        print(" [+] Windows Defender Log collection scan completed")

