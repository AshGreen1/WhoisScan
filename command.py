import subprocess
import colors
import signal
import sys

class commandLine():

    # Normal Command
    def normal(command): # list
        line = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (out,error) = line.communicate()
        output = out.decode()
        return output

    # status
    def status(command): # list
        line = subprocess.Popen(command,shell=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time = line.wait()
        return time
        
    def ctrl_c():
        def def_handler(sig, frame):
            print(colors.colorize("Killing all the processes...\n",'red','warning'))
            sys.exit(1)

        # Ctrl + C
        signal.signal(signal.SIGINT, def_handler)
