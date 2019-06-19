# http://dnsviz.net/
# https://dnssec-analyzer.verisignlabs.com/

# libraries
from myClass.traceDATA import traceDATA
import subprocess
import os

# commands
cmdig = "dig +dnssec"
cmdtrace = "dig +trace"
site =  "www.ariel.ac.il"
DIGcommand = cmdig + ' ' + site
TRACEcommand = cmdtrace + ' ' + site

# this function checks flag field of DNSSEC
def checkDNSSEC(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    p.wait()  
    for line in p.stdout:
        if ("EDNS" in str(line)):
            items = str(line)
            items = items.replace(';', '')
            items = items.split()
            for count, item in enumerate(items):
                if (item == 'flags:'):
                    if (items[count+1] == 'do'):              # do - DNSSEC
                        return True
                    else:
                        print(items[count+1])
                        return False
            return False

# this function parses the trace command
def traceDNSSEC(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    p.wait()
    oldline = ''
    for line in p.stdout:
        items = str(line)
        if ('Received' in items):
            workline1 = oldline.split()      # RRSIG line
            workline2 = items.split()        # Received line
            try:
                if (len(workline1) == 5):
                    algorithm = "Null"
                    name = workline1[0]
                    raddress = workline2[5]
                    print("Algorithm: "+"Null"+" Name: "+workline1[0])
                    print("Raddress: "+workline2[5])
                else:
                    algorithm = workline1[5]
                    name = workline1[0]
                    raddress = workline2[5]
                    print("Algorithm: "+workline1[5]+" Name: "+workline1[0])
                    print("Raddress: "+workline2[5])
            except Exception:
                algorithm = "Null"
                name = workline1[0]
                raddress = workline2[5]
                print("Algorithm: "+"Null"+" Name: "+workline1[0])
                print("Raddress: "+workline2[5])
            # insert into traceDATA object and print
            a = traceDATA(name, 0, algorithm, raddress)
            a.prinTrace()
        oldline = items

if __name__ == "__main__":
    flag = checkDNSSEC(DIGcommand)
    if (flag):
        print("DNSSEC")
    else:
        print("NO DNSSEC")

    traceDNSSEC(TRACEcommand)
