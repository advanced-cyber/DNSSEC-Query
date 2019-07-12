# libraries
import csv
import argparse

if __name__ == "__main__":
    # construct the argument parse and parse the arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--csv", required=True, help="path to csv file")
    args = vars(ap.parse_args())
    csv_file = args['csv']
    counter = [0, 0, 0, 0]
    # read csv file
    with open(csv_file) as csv_file:
        # read site csv file
        csv_reader = csv.reader(csv_file, delimiter=',')
        # skip first row (fields)
        next(csv_reader)
        for row in csv_reader:
            if row[0] is None:
                continue
            print(row)
            row = row[0].split(';')
            first_boolean = eval(row[1])
            second_boolean = eval(row[2])
            if(first_boolean and second_boolean):
                counter[3] += 1
            elif(first_boolean):
                counter[2] += 1
            elif(second_boolean):
                counter[1] += 1
            else:
                counter[0] += 1
    csv_file.close()
    print("Reading complete")

    # write new csv file with statistic
    new_csv = 'statistic_overall_results.csv' 
    with open(new_csv, 'w') as csv_file:
        fieldnames = ['False_False', 'False_True', 'True_False', 'True_True']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'False_False': counter[0], 'False_True': counter[1], 'True_False': counter[2], 'True_True': counter[3]})
    csv_file.close()
    print("Writing complete")
    
