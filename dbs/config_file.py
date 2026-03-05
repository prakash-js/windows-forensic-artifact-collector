class configuration_file:
    def __init__(self):
        self.api_key = {
            "api_value": "your_hybrid_analysis_api_key"
        }

        self.whitelisted_ips = {
            "ip_address": {'8.8.8.8',
                           '127.0.0.1',
                           '8.8.4.4' ,
                           '1.1.1.1',
                           '224.0.0.251',
                           'ff02::fb','::1'
                           }
        }

        self.directory_config = {
            "directories": ['',
                
                            ]

        }
