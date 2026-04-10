class configuration_file:
    def __init__(self):

        #Add your Hybrid Analysis API key here.
        self.api_key = {
            "api_value": "your_hybrid_analysis_api_key"
        }

        # IPs listed below are whitelisted from firewall logs. Users can add more IPs if required.
        self.whitelisted_ips = {
            "ip_address": {'8.8.8.8',
                           '127.0.0.1',
                           '8.8.4.4' ,
                           '1.1.1.1',
                           '224.0.0.251',
                           'ff02::fb','::1',
                           '142.251.32.110'}
        }

        # Add directories here. Only directories listed in this section will be analyzed.
        # Use escaped backslashes ('\\')
        self.directory_config = {
            "directories": ['C:\\',
                            'C:\\Users\\',
                            ]
        }
