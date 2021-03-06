import subprocess
import platform
import os

def capture():
    curDirWorking = os.getcwd()
    fileBat = curDirWorking + "\\tshark.bat"
    fileBash  = curDirWorking + "/tshark.sh"

    if platform.system() == "Windows":
        p = subprocess.Popen(fileBat, shell=True, stdout = subprocess.PIPE)
        # stdout, stderr = p.communicate()
        p.communicate()
        print(p.returncode)  # is 0 if success
    elif platform.system() == "Linux":
        os.system("gnome-terminal --execute bash %s" %fileBash)
        # p = subprocess.call(fileBash, creationflags=2, shell=True)
    else:
        print("Sorry, we do not support your system")

