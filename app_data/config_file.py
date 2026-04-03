class configuration_file:
    def __init__(self):
        self.api_key = {
            "api_value": "95p3cu8kabef50d7srwhemlp16623c293zxz9qyqfb2f6b69lpc4n9d3339f0396"
        }

        self.whitelisted_ips = {
            "ip_address": {'8.8.8.8',
                           '127.0.0.1',
                           '8.8.4.4' ,
                           '1.1.1.1',
                           '224.0.0.251',
                           'ff02::fb','::1',
                           '142.251.32.110'}
        }

        #make sure to use character escape  '\\'
        self.directory_config = {
            "directories": ['C:\\AMD\\Radeon-Software-Adrenalin-2020-22.6.1-Win10-Win11-64Bit-LegacyASICs-June23-2022-LEGACY\\Bin64',
                            'C:\\Users\\gryco\\Downloads\\',
                             'C:\\Users\\gryco\\Documents\\'
                            ]
        }