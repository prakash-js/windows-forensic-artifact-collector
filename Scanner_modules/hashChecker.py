import requests
from dbs.hash_db import hashStoring
from dbs.config_file import configuration_file
hs = hashStoring()
HA = configuration_file()

class hash_checking:

    def __init__(self):
        self.api_key = HA.api_key.get('api_value')
        self.URL = "https://www.hybrid-analysis.com/api/v2/search/hash"


    def hash_checker(self,hash_out,scan_value):

        if not scan_value:
            print(scan_value)
            return "un-detected"

        # with open('../config_files/hybrid-analysis-api.txt' , 'r') as api_file:
        #     self.api_key = api_file.read()

        headers_value =  {
            "User-Agent": "Falcon",
            "api-key": f"{self.api_key}.",  # make a  API LOGIC
            "accept": "application/json"
        }

        key = hash_out.strip().lower()

        if hash_out is not None:

            clean_hash = hash_out.strip().lower()
            if clean_hash in hs.hash_dict:
                return hs.hash_dict[clean_hash]

            else:
                params = {
                    "hash": hash_out.strip().lower()
                }
                try:
                    req = requests.get(f"{self.URL}" , headers=headers_value, params=params, timeout=10)

                except Exception as e:
                    return "un-detected"

                if req.status_code != 200:
                    if hash_out.strip().lower() not in hs.hash_dict:
                        hs.hash_dict[key] = "Unknown"
                        pass
                    return "Unknown"

                data = req.json()
                reports = data.get("reports", [])

                if not reports:
                    if hash_out.strip().lower() not in hs.hash_dict:
                        hs.hash_dict[key] = "Unknown"
                    return "Unknown"

                verdict = reports[0].get("verdict")

                if verdict == "no specific threat":
                    if hash_out.strip().lower() not in hs.hash_dict:
                        hs.hash_dict[key] = "no specific threat"
                    return "Unknown"

                if verdict == "whitelisted":
                    if hash_out.strip().lower() not in hs.hash_dict:
                        hs.hash_dict[key] = "whitelisted"
                    return "whitelisted"

                if verdict == "":
                    return "Unknown"

                if hash_out.strip().lower() not in hs.hash_dict:
                    hs.hash_dict[key] = "Unknown"



#
# import requests
# from dbs.hash_db import hashStoring
# hs = hashStoring()
#
# class hash_checking:
#
#     def __init__(self):
#         #self.hash = open()
#         self.URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
#         self.HEADERS = {
#             "User-Agent": "Falcon",
#             "api-key": "65vq2h7i7182d347fme6ad6sb63ddec6p3nkddm086a81a3acbr4bf0ad9ed81e5",
#             "accept": "application/json"
#         }
#
#
#
#     def hash_checker(self,hash_out):
#
#
#
#         key = hash_out.strip().lower()
#
#         if hash_out is not None:
#
#             clean_hash = hash_out.strip().lower()
#             if clean_hash in hs.hash_dict:
#                 return hs.hash_dict[clean_hash]
#
#             else:
#                 params = {
#                     "hash": hash_out.strip().lower()
#                 }
#
#                 try:
#                     req = requests.get(f"{self.URL}" , headers=self.HEADERS, params=params, timeout=10)
#
#                 except Exception as e:
#                     return "un-detected"
#
#                 if req.status_code != 200:
#                     if hash_out.strip().lower() not in hs.hash_dict:
#                         hs.hash_dict[key] = "Unknown"
#                         pass
#                     return "Unknown"
#
#                 data = req.json()
#                 reports = data.get("reports", [])
#
#                 if not reports:
#                     if hash_out.strip().lower() not in hs.hash_dict:
#                         hs.hash_dict[key] = "Unknown"
#                     return "Unknown"
#
#                 verdict = reports[0].get("verdict")
#
#                 if verdict == "no specific threat":
#                     if hash_out.strip().lower() not in hs.hash_dict:
#                         hs.hash_dict[key] = "no specific threat"
#                     return "Unknown"
#
#                 if verdict == "whitelisted":
#                     if hash_out.strip().lower() not in hs.hash_dict:
#                         hs.hash_dict[key] = "whitelisted"
#                     return "whitelisted"
#
#                 if verdict == "":
#                     return "Unknown"
#
#                 if hash_out.strip().lower() not in hs.hash_dict:
#                     hs.hash_dict[key] = "Unknown"
#
#
# hs_f = hash_checking()
#


