import platform
import os
import subprocess
import socket


def check_internet_connection():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("Internet connection OK")
    except OSError:
        print("No Internet Connection")
        print("\n")
        print(
            rf'''
            No Internet connection is available. As a result, the required forensic tools cannot be downloaded automatically.

            Please download the tools manually based on your system architecture (32-bit or 64-bit) from the official NirSoft pages below:

            * WinPrefetchView: https://www.nirsoft.net/utils/win_prefetch_view.html
            * USBdrivelog: https://www.nirsoft.net/utils/usbdrivelog.zip

            After downloading, extract the tools and place them in the appropriate directory before proceeding .
            {os.path.join(os.getcwd(), "forensic_tools")}
            '''

        )
        exit()


def downloading_tool():
    arch = platform.architecture()[0]
    current_path = os.getcwd()
    final_path = os.path.join(current_path, 'forensic_tools')

    cmd3 = fr"curl -o '{final_path}\\usbdrivelog.zip' https://www.nirsoft.net/utils/usbdrivelog.zip"
    try:
        subprocess.run(["powershell", "-command", cmd3], capture_output=True, text=True)

    except Exception as e:
        print(e)

    cmd4 = fr"Expand-Archive -Path '{final_path}\\usbdrivelog.zip' -DestinationPath '{final_path}'"
    try:
        subprocess.run(["powershell", "-command", cmd4], capture_output=True, text=True)
        print(\n [+] "The usbdrivelog tool has been downloaded and extracted successfully.")
    except Exception as e:
        print(e)

    if arch == '64bit':
        cmd = fr"curl -o '{final_path}\\winprefetchview.zip' https://www.nirsoft.net/utils/winprefetchview-x64.zip"
        try:
            subprocess.run(["powershell", "-command", cmd], capture_output=True, text=True)
        except Exception as e:
            print(e)

        cmd2 = fr"Expand-Archive -Path '{final_path}\\winprefetchview.zip' -DestinationPath '{final_path}'"
        try:
            subprocess.run(["powershell", "-command", cmd2], capture_output=True, text=True)
            print(\n [+] "The WinPrefetchView tool has been downloaded and extracted successfully.")
        except Exception as e:
            print(e)


    elif arch == '32bit':
        current_path = os.getcwd()
        final_path = os.path.join(current_path, 'forensic_tools')

        cmd = fr"curl -o {final_path}\\winprefetchview.zip https://www.nirsoft.net/utils/winprefetchview.zip"
        try:
            subprocess.run(["powershell", "-command", cmd], capture_output=True, text=True)
        except Exception as e:
            print(e)

        cmd2 = fr"Expand-Archive -Path '{final_path}\\winprefetchview.zip' -DestinationPath '{final_path}'"
        try:
            subprocess.run(["powershell", "-command", cmd2], capture_output=True, text=True)
            print(\n [+] "The WinPrefetchView tool has been downloaded and extracted successfully.")
        except Exception as e:
            print(e)


def check_tools():
    if not os.path.exists(os.path.join(os.getcwd(), "forensic_tools\\WinPrefetchView.exe")):
        print(f"""
                WinPrefetchView.exe is not found in the expected directory.

                Please download it manually from:
                WinPrefetchView: https://www.nirsoft.net/utils/win_prefetch_view.html

                After downloading, extract the contents into the following directory:
                {os.path.join(os.getcwd(), "forensic_tools")}
                """)
    else:
        pass

    if not os.path.exists(os.path.join(os.getcwd(), "forensic_tools\\USBDriveLog.exe")):
        print(f"""
                USBDriveLog.exe is not found in the expected directory.

                Please download it manually from:
                USBDriveLog.exe: https://www.nirsoft.net/utils/usbdrivelog.zip

                After downloading, extract the contents into the following directory:
                {os.path.join(os.getcwd(), "forensic_tools")}
                """)
    else:
        pass

     if  os.path.exists(os.path.join(os.getcwd(), "forensic_tools\\WinPrefetchView.exe")) and os.path.exists(os.path.join(os.getcwd(), "forensic_tools\\USBDriveLog.exe")):
         print("\n [+] The setup has completed successfully.")


check_internet_connection()
downloading_tool()
check_tools()
