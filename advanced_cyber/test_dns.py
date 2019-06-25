# http://dnsviz.net/
# https://dnssec-analyzer.verisignlabs.com/

# Type the following command to start BIND server:
# service bind9 start

# Type the following command to stop BIND server:
# service bind9 stop

# Type the following command to restart BIND server:
# service bind9 restart

# Type the following command to reload BIND server to reload zone file or config file changes:
# service bind9 reload

# Type the following command to see the current status of BIND server:
# service bind9 status

# libraries
from myClass.traceDATA import traceDATA
import subprocess
import os
import csv
import numpy as np

# commands
cmdig = "dig +dnssec"
cmdtrace = "dig +trace"

# CSV File
loc = 'dnssec.csv'



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
def traceDNSSEC(command, key):
    query_flag = True            # this flag saves the overall result for the query
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    p.wait()
    oldline = ''
    secflag = 0
    rows = []
    for line in p.stdout:
        items = str(line)
        if ('Received' in items):
            workline1 = oldline.split()      # RRSIG line
            workline2 = items.split()        # Received line
            try:
                if (len(workline1) == 5):
                    algorithm = -1
                    name = workline1[0]
                    raddress = workline2[5]
                    query_flag = False            # no dnssec in trace, if all rows reach this stage with secflag=1, the query_flag will be 1
                else:
                    algorithm = workline1[5]
                    name = workline1[0]
                    raddress = workline2[5]
                    if (workline1[3] == 'RRSIG'):
                        secflag = 1
            except Exception:
                algorithm = -1
                name = workline1[0]
                raddress = workline2[5]
                query_flag = False            # no dnssec in trace, if all rows reach this stage with secflag=1, the query_flag will be 1
            a = traceDATA(key, name, secflag, algorithm, raddress)
            rows.append(a)
            secflag = 0 
        oldline = items
    return (query_flag, rows)

if __name__ == "__main__":
    with open(loc) as csv_sites:
        with open('overall_results.csv', mode='w') as overall_results:
            with open('trace_results.csv', mode='w') as trace_results:

                # defining headers of csv files
                overall_fields = ["Website", "Dig DNSSEC Flag", "Trace Query Flag"]
                trace_fields = ["Website", "Partial Query", "SecFlag", "Algorithm", "Received Address"]

                # write header of overall_results
                overall_writer = csv.DictWriter(overall_results, fieldnames = overall_fields,  extrasaction='ignore', delimiter = ';')
                overall_writer.writeheader()
                # write header of trace_results
                trace_writer = csv.DictWriter(trace_results, fieldnames = trace_fields,  extrasaction='ignore', delimiter = ';')
                trace_writer.writeheader()

                # read site csv file
                read_csv_sites = csv.reader(csv_sites, delimiter=',')

                # skip first row (fields)
                next(read_csv_sites)

                # for row in sites csv
                for (i, row) in enumerate(read_csv_sites):

                    site =  row[1]
                    DIGcommand = cmdig + ' ' + site
                    TRACEcommand = cmdtrace + ' ' + site
     
                    # dig command for current website
                    flag = checkDNSSEC(DIGcommand)

                    # trace overall answer is held in trace_ans
                    trace_ans, rows = traceDNSSEC(TRACEcommand, site)
           
                    for row in rows:
                        trace_writer.writerows([{'Website': row.getKey(), 'Partial Query': row.getName(), 'SecFlag': row.getSecFlag(), 'Algorithm': row.getAlgorithm(), 'Received Address': row.getRAddress()}])

                    # writing overall answers into overall_results csv file
                    overall_writer.writerows([{'Website': site, 'Dig DNSSEC Flag': flag, 'Trace Query Flag': trace_ans}])
                    
                    # show an update every 50 websites
                    if (i > 0 and i % 50 == 0):
                        print("[INFO] processed {}/{}".format(i, 544))

