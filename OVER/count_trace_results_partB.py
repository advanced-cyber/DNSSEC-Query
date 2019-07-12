# libraries
import csv
import argparse
import itertools

if __name__ == "__main__":
    # construct the argument parse and parse the arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--csv", required=True, help="path to csv file")
    args = vars(ap.parse_args())
    csv_file = args['csv']
    # 0,Delete DS,DELETE                      1,"RSA/MD5 (deprecated, see 5)",RSAMD5                  2,Diffie-Hellman,DH
    # 3,DSA/SHA1,DSA                          4,Reserved                                              5,RSA/SHA-1,RSASHA1
    # 6,DSA-NSEC3-SHA1,DSA-NSEC3-SHA1         7,RSASHA1-NSEC3-SHA1,RSASHA1-NSEC3-SHA1                 8,RSA/SHA-256,RSASHA256
    # 9,Reserved                              10,RSA/SHA-512,RSASHA512                                11,Reserved
    # 12,GOST R 34.10-2001,ECC-GOST           13,ECDSA Curve P-256 with SHA-256,ECDSAP256SHA256       14,ECDSA Curve P-384 with SHA-384,ECDSAP384SHA384
    # 15,Ed25519,ED25519                      16,Ed448,ED448                                          17-122,Unassigned
    # 123-251,Reserved                        252,Reserved for Indirect Keys,INDIRECT                 253,private algorithm,PRIVATEDNS
    # 254,private algorithm OID,PRIVATEOID    255,Reserved
    algorithms = ['DELETE', 'RSAMD5', 'Diffie-Hellman', 'DSA/SHA1', '4_Reserved', 'RSA/SHA-1', 'DSA-NSEC3-SHA1', 'RSASHA1-NSEC3-SHA1', 'RSA/SHA-512', '9_Reserved', 'ECC-GOST', 'ECDSAP256SHA256', 'ECDSAP384SHA384', 'ED25519', 'ED448', 'Unassigned', '123_251_Reserved', 'INDIRECT', 'PRIVATEDNS', 'PRIVATEOID', '255_Reserved']
    counter_algorithm = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # first - TLD, second - middle and end
    counter_insecure = [0, 0, 0, 0, 0, 0]
    index_counter_insecure = 0
    # read csv file
    with open(csv_file) as csv_file:
        # read site csv file
        csv_reader = csv.reader(csv_file, delimiter=',')
        # skip first row (fields)
        #next(csv_reader)
        tmp_website = ''
        flag_insecure = True
        for row in csv_reader:
            if(row[0] == ''):
                continue
            website = row[0]
            status = row[5]
            algorithm = int(row[3])
            if (website != tmp_website):
                tmp_website = website
                flag_insecure = True
                index_counter_insecure = 0
                if (status == 'INSECURE'):
                    flag_insecure = False
                    counter_insecure[index_counter_insecure] += 1 
            if(flag_insecure and (status == 'INSECURE' or status == 'NO')):
                flag_insecure = False
                counter_insecure[index_counter_insecure] += 1 
            index_counter_insecure += 1 
            if(-2 < algorithm < 1):
                 counter_algorithm[0] += 1
            elif(algorithm == 1):
                 counter_algorithm[1] += 1
            elif(algorithm == 2):
                 counter_algorithm[2] += 1
            elif(algorithm == 3):
                 counter_algorithm[3] += 1
            elif(algorithm == 4):
                 counter_algorithm[4] += 1
            elif(algorithm == 5):
                 counter_algorithm[5] += 1
            elif(algorithm == 6):
                 counter_algorithm[6] += 1
            elif(algorithm == 7):
                 counter_algorithm[7] += 1
            elif(algorithm == 8):
                 counter_algorithm[8] += 1
            elif(algorithm == 9):
                 counter_algorithm[9] += 1
            elif(algorithm == 10):
                 counter_algorithm[10] += 1
            elif(algorithm == 11):
                 counter_algorithm[11] += 1
            elif(algorithm == 12):
                 counter_algorithm[12] += 1
            elif(algorithm == 13):
                 counter_algorithm[13] += 1
            elif(algorithm == 14):
                 counter_algorithm[14] += 1
            elif(algorithm == 15):
                 counter_algorithm[15] += 1
            elif(algorithm == 16):
                 counter_algorithm[16] += 1
            elif(17 <= algorithm <= 122):
                 counter_algorithm[17] += 1
            elif(123 <= algorithm <= 251):
                 counter_algorithm[18] += 1
            elif(algorithm == 252):
                 counter_algorithm[19] += 1
            elif(algorithm == 253):
                 counter_algorithm[20] += 1
            elif(algorithm == 254):
                 counter_algorithm[21] += 1
            else:
                 counter_algorithm[22] += 1
    csv_file.close()
    print("Reading complete")

    # write new csv files with statistic
    new_csv_algorithm = 'statistic_trace_algorithm_results.csv'
    new_csv_insecure = 'statistic_trace_insecure_results.csv' 
    with open(new_csv_algorithm, 'w') as csv_file:
        fieldnames = ['Algorithm', 'Number']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for alg,num in itertools.izip(algorithms,counter_algorithm):
            writer.writerow({'Algorithm': alg, 'Number': num})
    csv_file.close()
    print("Algorithm. Writing complete")

    with open(new_csv_insecure, 'w') as csv_file:
        fieldnames = ['Root', 'TLD', 'Layot_1', 'Layot_2', 'Layot_3', 'Layot_4']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Root': counter_insecure[0], 'TLD': counter_insecure[1], 'Layot_1': counter_insecure[2], 'Layot_2': counter_insecure[3], 'Layot_3': counter_insecure[4], 'Layot_4': counter_insecure[5]})
    csv_file.close()
    print("Insecure. Writing complete")
