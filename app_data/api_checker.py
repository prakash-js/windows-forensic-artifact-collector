import requests
import socket


class ApiConnectionHandler:

    def checking_request(self,api):
        url = "https://www.hybrid-analysis.com/api/v2/key/current"
        headers = {
            "User-Agent": "Falcon",
            "api-key": f"{api}",
            "accept": "application/json"
        }
        try:
            response = requests.get(url, headers=headers,timeout=6)
        except Exception as HTTPSConnectionPool:
            print(HTTPSConnectionPool)
            return False

        if response.status_code == 200:
            print("API key is valid")
            # with open('hybrid-analysis-api.txt', 'w') as api_file:
            #     api_file.write(api.strip())
            return True

        else:
            print("Error:", response.status_code, response.text)
            self.checking_api()
            return False



    def checking_api(self):
        empty_list = []

        with open('hybrid-analysis-api.txt', 'r') as api_file:
            empty_list.append(api_file.readline())
            if not empty_list[0]:
                print(empty_list[0])
                print("There is no api key")
                while True:
                    answer = input("There is no API key present. Do you want to add one? (Yes/No)")
                    if answer.lower() == "no":
                        print("See the README for instructions on adding the API key manually. File hash analysis is not performed in this scan.")
                        return False

                    if answer.lower() == "yes":
                        api_key = input("Enter the API key :")
                        self.checking_request(api_key)
                        break

            if  empty_list[0]:
                print("There is api key")
                for idx , i in enumerate(empty_list):
                    if idx == 0:
                        self.checking_request(i.strip())
                    else:
                        break

    def is_internet_available(self):
        connection = None
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            connection = True
        except OSError:
            connection = False

        if not connection:
            print("No internet connection detected. Threat analysis will not work. Continuing without the Threat Analyzer.")
            return False
