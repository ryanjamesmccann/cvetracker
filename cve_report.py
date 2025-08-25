import sys
import getopt
import os
import json

infile = "in.json"
outfile = "out.csv"
show_all = False
show_summary = False
show_unknown = False
compare_reports_bool = False
compared_report = ""
to_csv = False
date = ""
all = False
file_directory = f"/Users/ryanmccann/code/Dad_CVE_Project/cve_test/"
report_folder = f"/Users/ryanmccann/code/Dad_CVE_Project/unpatched_cve_report/reports"
important_data = {}


def show_syntax_and_exit(code):
    """
    Show the program syntax and exit with an errror
    Arguments:
        code: the error code to return
    """
    print("Syntax: %s [-h] [-a] [-s] [-c] [-u] [-i inputfile][-o outputfile]" % sys.argv[0])
    print("Default files: in.json and out.csv")
    print(
        "Use -c or --to-csv to generate a CSV report, output file is then needed, out.csv by default"
    )
    print("Use -a or --all to list all issues, otherwise we filter only unpatched ones")
    print("Use -s or --summary to show a summary of the issues")
    print("Use -u or --unknown to list unknown issues")
    print("Use -d or --date to input the date you want for your report")
    print("Use -x or --x to make a report of all the cve files in the folder")
    print("Use -y or --compare to compare two reports")
    sys.exit(code)


def exit_error(code, message):
    """
    Show the error message and exit with an errror
    Arguments:
        code: the error code to return
        message: the message to show
    """
    print("Error: %s" % message)
    sys.exit(code)


def parse_args(argv):
    """
    Parse the program arguments, put options in global variables
    Arguments:
        argv: program arguments
    """
    global infile, outfile, show_all, show_summary, to_csv, date, all, compare_reports_bool, compared_report
    try:
        opts, args = getopt.getopt(
            argv, "hi:o:ascud:xy:", ["help", "input", "output", "summary", "to-csv", "unknown", "date", "all", "x", "compare"]
        )
    except getopt.GetoptError:
        show_syntax_and_exit(1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            show_syntax_and_exit(0)
        elif opt in ("-a", "--all"):
            show_all = True
            show_unknown = True
        elif opt in ("-i", "--input"):
            infile = arg
        elif opt in ("-c", "--to-csv"):
            to_csv = True
            print("to_csv is set to True.")
        elif opt in ("-o", "--output"):
            outfile = arg
        elif opt in ("-s", "--summary"):
            show_summary = True
        elif opt in ("-u", "--unknown"):
            show_unknown = True
        elif opt in ("-d", "--date"):
            date = arg
        elif opt in ("-x", "--x"):
            all = True
            print("All is now set to True")
        elif opt in ("-y," "--compare"):
            if arg != "None":
                compare_reports_bool = True
                compared_report = str(arg).split(".")


def load_json(filename):
    """
    Load the JSON file, return the resulting dictionary
    Arguments:
        filename: the file to open
    Returns:
        Parsed file as a dictionary
    """

    out = {}
    global file_directory
    try:
        os.makedirs(file_directory, exist_ok = True)
        file_path = os.path.join(file_directory, filename)
        with open(file_path, "r") as f:
            out = json.load(f)
            print("Loaded JSON data")  
            return out
    except FileNotFoundError:
        exit_error(1, "Input file (%s) not found" % (filename))
    except json.decoder.JSONDecodeError as error:
        exit_error(1, "Malformed JSON file: %s" % str(error))
    return out


def do_all():
    """
    Gets all JSON data from every file in cve folder
    Returns:
        list of all files
    """
    global file_directory
    out = {}
    files = {}
    print("In function do_all. Trying to load all the data from .json files in cve folder...")
    for file in os.listdir(file_directory):
        print(f"\nLoading file: {file}...\n")
        if file.__contains__(".json"):
            filename = file
            files[filename] = {}
            print(f"\nTrying to load {filename} from do_all\n")
            try:
                os.makedirs(file_directory, exist_ok = True)
                file_path = os.path.join(file_directory, filename)
                with open(file_path, "r") as f:
                    file_data = (json.load(f))
                    out = file_data
                    files[filename] = out
                    print(out)
                    print(f"\nLoaded JSON data from {filename}. Added the data to list of files in cve.\n")          
            except json.decoder.JSONDecodeError as error:
                exit_error(1, "Malformed JSON file: %s" % str(error))
                print("_______ERROR______ jsonDecodeError")
    print(f"\nFILES: {files}\n")
    return files

def process_data(filename, infile, data, unpatched_only, do_summary, do_csv, date):
    """
    Write the resulting CSV with one line for each package
    Arguments:
        filename: the file to write to
        data: dictionary from parsing the JSON file
        unpatched_only: True if we want only unpatched issues, False otherwise
        do_summary: writes summary
        do_csv: True if we want to generate the csv report, False otherwise
        date: the date we want for the name of the report
    """

    print(f"We are in the function process_data for {filename}")
    print(f"do_csv = {do_csv}")

    if not "version" in data or data["version"] != "1":
        exit_error(1, "Unrecognized format version number")
    if not "package" in data:
        exit_error(1, "Mandatory 'package' key not found")

    lines = ""
    total_issue_count = 0
    for package in data["package"]:
        keys_in_package = {"name", "layer", "version", "issue"}
        if keys_in_package - package.keys():
            exit_error(
                1,
                "Missing a mandatory key in package: %s"
                % (keys_in_package - package.keys()),
            )

        package_name = package["name"]
        layer = package["layer"]
        package_version = package["version"]
        package_summary = "Issues for package %s (version %s):\n\t" % (
            package_name,
            package_version,
        )
        unpatched_summary = ""
        unknown_summary = ""
        issue_count = 0

        for issue in package["issue"]:
            keys_in_issue = {"id", "scorev2", "scorev3", "vector", "status"}

            cve_id = issue["id"]
            if "summary" in issue:
                summary = issue["summary"]
                print(f"\nSUMMARY VARIABLE = summary\n")
            else:
                summary = "No Summary"
            if "scorev2" in issue:
                scorev2 = issue["scorev2"]
            else:
                scorev2 = 0.0
            if "scorev3" in issue:
                scorev3 = issue["scorev3"]
            else:
                scorev3 = 0.0
            if "vector" in issue:
                vector = issue["vector"]
            else:
                vector = ""
            if "status" in issue:
                status = issue["status"]
                print(status)
            else:
                status = ""
            if (unpatched_only == False) or (status == "Unpatched") or \
                (show_unknown == True and status == "Unknown"):

                remediation = ""
                
                
                

                if do_csv:

                    folder_path = (f"/Users/ryanmccann/code/Dad_CVE_Project/unpatched_cve_report/{date}")
                    os.makedirs(folder_path, exist_ok=True)
                    
                    make_unpatched_txt(filename, folder_path, cve_id, package_name, status, scorev3, summary, remediation)
                    make_unpatched_json(filename, folder_path, cve_id, package_name, status, scorev3, summary, remediation)
                    

                lines += "%s;%s;%s;%s;%s;%s;%s\n" % (
                    layer,
                    package_name,
                    package_version,
                    cve_id,
                    scorev2,
                    scorev3,
                    vector,
                )
                if status == "Unpatched":
                    unpatched_summary += "%s " % (cve_id)
                elif status == "Unknown":
                    unknown_summary += "%s " % (cve_id)
                issue_count += 1

        
        if do_summary and issue_count > 0:
            package_summary += "\n\tUnpatched: "
            package_summary += unpatched_summary
            if show_unknown:
                package_summary += "\n\tUnknown: "
                package_summary += unknown_summary
            package_summary += "\n\tCount: %d\n" % (issue_count)
            print()
            print("-------------------------------------------------------------------------")
            print()
            print("PACKAGE SUMMARY")
            print(package_summary)
            print()
            print("-------------------------------------------------------------------------")
            print()

        total_issue_count += issue_count

    

    if do_summary:
        print("Global issue count: %d" % (total_issue_count))

    update_base_database(filename, infile, data)



def make_unpatched_json(filename, folder_path, cve_id, package_name, status, scorev3, summary, remediation):
    """
    Makes json file of unpatched cves
    """
    filename_json = os.path.join(folder_path, f"{filename}.json")
    if os.path.exists(filename_json):
        with open(filename_json, "r") as f:
            existing = json.load(f)
    else:
        existing = {"issues": []}

    existing["issues"].append(
        {"id": cve_id,
        "package name": package_name,
        "status": status,
        "scorev3": scorev3,
        "summary": summary,
        "remediation": remediation})

    with open(filename_json, "w") as outjson:
        json.dump(existing, outjson, indent=4)

def make_json(filename, folder_path, data):
    """
    Makes json file
    """
    filename_json = os.path.join(folder_path, f"{filename}.json")
    with open(filename_json, "w") as outjson:
        print(f"Printing {filename}")
        json.dump(data, outjson, indent = 4)
    

def make_unpatched_txt(filename, folder_path, cve_id, package_name, status, scorev3, summary, remediation):
    """
    Makes txt file of unpatched cve
    """
    csv_info_txt = (f"{cve_id}; {package_name}; {status}; {scorev3}; {summary}; Remediation: {remediation}\n")
    filename_txt = os.path.join(folder_path, f"{filename}.txt")           
    with open(filename_txt, "a") as outtxt:
        print(f"Printing {filename_txt}")
        outtxt.write(str(csv_info_txt))

def make_txt(filename, folder_path, data):
    """
    Makes txt file
    """
    filename_txt = os.path.join(folder_path, f"{filename}.txt")           
    with open(filename_txt, "w") as outtxt:
        print(f"Printing {filename_txt}")
        outtxt.write(str(data))

def update_base_database(filename, infile, data):
    """
    Adds file to base database if file doesn't exist there.
        Updates old data if it exists.
    Arguments: 
        filename: the file name
        infile: the input file
        data: the data of the file
    """

    ## Making Base Database

    print()
    print("IN UPDATE-BASE-DATABASE FUNCTION")
    print()

    base_directory = "/Users/ryanmccann/code/Dad_CVE_Project/cve_base_database/"
    os.makedirs(base_directory, exist_ok = True)
    database_list = os.listdir(base_directory)
    
    
    
    if not os.path.isfile(f"{base_directory}{filename}"):
        make_json(filename, base_directory, data)

    if not os.path.isfile(f"{base_directory}{infile}"):
        make_txt(infile, base_directory, data)


def load_report(date):
    """
    Opens unpatched report and writes a .txt file of the report. 
    Returns the report path and the folder path.
    """

    this_folder = (f"/Users/ryanmccann/code/Dad_CVE_Project/unpatched_cve_report/{date}")

    print(f"Loading Report for {date}")

    todays_unpatched_cve_report = f"unpatched_report_{date}.txt"
    report_path = os.path.join(report_folder, todays_unpatched_cve_report)

    os.makedirs(this_folder, exist_ok=True)

    all_lines = []

    for txt_file in os.listdir(this_folder):
        txt_path = os.path.join(this_folder, txt_file)
        print(txt_path)
        
        if not txt_file.endswith(".txt") or not os.path.isfile(txt_path):
            print(f"Skipping: {txt_file} — not a .txt file or not a regular file")
            continue
        else:
            print(f"Generating {date} report...")
            print(f"Opening: {txt_path}")
            with open(txt_path, "r") as t:
                print(f"Checking: {txt_file} | Path: {txt_path}")
                lines = t.read()
                print(f"Lines = {lines}")
                all_lines.append(lines)

        with open(report_path, "w") as f:
            for line in all_lines:
                f.write(line)
                            
    return report_path, all_lines

def compare_reports(date, current_report_path, date_to_compare):
    """Compares new report with a previous report that you input. 
        Returns current_report"""
    print(current_report_path)
    date_to_compare_path = (f"/Users/ryanmccann/code/Dad_CVE_Project/unpatched_cve_report/reports/unpatched_report_{date_to_compare}.txt")

    current_report = []
    latter_report = []
    current_report_cve_dict = {}
    latter_report_cve_dict = {}
    split_line = []
    current_cve = []
    latter_cve = []

    with open(current_report_path, "r") as f:
        print(f"Opening file:{current_report_path}")
        for line in f:
            line_representation = repr(line)
            print("The representation of the line is: " + line_representation)
            if line.strip() == "":
                print("This line is a line n")
            else:
                split_line = str(line).split(";")
                print("This is split_line[0]:" + split_line[0])
                current_report.append(str(split_line))
                current_cve.append(split_line[0])
                print(f"current_cve = {current_cve}")
                current_report_cve_dict[split_line[0]] = split_line[1:]

    with open(date_to_compare_path, "r") as f:
        print(f"Opening file:{date_to_compare_path}")
        for line in f:
            line_representation = repr(line)
            print("The representation of the line is: " + line_representation)
            if line.strip() == "":
                print("This line is a line n")
            else:
                split_line = str(line).split(";")
                latter_cve.append(split_line[0])
                print(f"latter_cve = {latter_cve}")
                latter_report_cve_dict[split_line[0]] = split_line[1:]

    """Finds the similarities and differences in the report and the report you are comparing."""
    same_cve = set(current_cve) & set(latter_cve)
    dif_cve = set(current_cve) - set(latter_cve)

    for cve in same_cve:
        if "Unpatched" in current_report_cve_dict[cve]:
            print(f"{cve} is still unpatched.")
        elif "Patched" in current_report_cve_dict[cve]:
            print(f"{cve} has been patched.")

    for cve in dif_cve:
        print(f"{cve} is a new unpatched CVE.")
    
    return current_report

def create_html(report_folder, date, current_report):
    """Write html file of the report."""
    cve = {}
    print(current_report)
    os.makedirs(report_folder, exist_ok=True)
    html = os.path.join(report_folder, f"{date}.html")
    i = 0
    x = 0
    fields = []

    with open(html, "w") as write:
        print()
        print("Writing html...")
        print(f"Writing html at {report_folder}")
        write.write("<!DOCTYPE html>\n<html>\n<head>\n<title>CVE Reports</title>\n<style> ... </style>\n</head>\n<body><table>\n<tr>\n<th>ID</th>\n<th>Title</th>\n<th>Status</th>\n<th>Severity</th>\n<th>Explanation</th>\n<th>Remediation</th>")

        for line in current_report:
            print(line)
            fields = line.strip().split(";")
            print(f"fields is{fields}")
            if len(fields) < 1:
                continue  # Skip malformed lines
            write.write("  <tr>\n")
            for field in fields:
                i +=1 
                if x > 0:
                    fields.insert(0, double_field[1])
                    print(f"adding{double_field[1]} to html. i = {i}")
                    write.write(f"    <td>{double_field[1].strip()}</td>\n")
                    x = 0
                    continue
                elif "\n" in field:
                    double_field = field.split("\n")
                    print("----------------------------------")
                    print(f"double_field[0] = {double_field[0]}")
                    print(f"double_field[1] = {double_field[1]}")
                    print("----------------------------------")
                    
                    print(f"adding REMEDIATION({double_field[0]}) to html. i = {i}")
                    write.write(f"    <td>{double_field[0].strip()}</td>\n")
                    write.write(" </tr> <tr>")
                    print(f"The next field to be added is: {double_field[1]}")   
                    x += 1
                else:
                    print(f"adding{field} to html. i = {i}")
                    write.write(f"    <td>{field.strip()}</td>\n")
                    x = 0
                
            write.write("  </tr>\n")
        
        print("wrote html.")

        write.write("</table></body></html>")


def main(argv):
    global infile, outfile, all, to_csv, compare_reports_bool, compared_report, report_folder, date
    print("In main. Parsing args...")
    parse_args(argv)
    print(f"Args were parsed. All is equal to {all}")
    if all == True:
        print("Going into function do_all()")
        data = do_all()
        print(f"Data loaded.")
        for filename, nested_data in data.items(): 
            nested_data = dict(nested_data)
            stripped_filename = filename.removesuffix(".json")
            outfile = stripped_filename
            print(f"show_all = {not show_all}")
            process_data(outfile, infile, nested_data, not show_all, show_summary, to_csv, date)

     

    elif all == False:
        print(f"ALL = {all}")
        data = load_json(infile)
        print(f"\n Data loaded.\n")
        print(f"Going into process_data.")
        process_data(outfile, infile, data, not show_all, show_summary, to_csv, date)
    else:
        print("Not working right.")

    
    date_folder = (f"/Users/ryanmccann/code/Dad_CVE_Project/unpatched_cve_report/{date}")
    if os.path.isdir(date_folder):
        print(f"{os.path.isdir(date_folder)}")
        print(date_folder)
        current_report_path, all_lines = load_report(date)
    
    if compare_reports_bool == True:
        current_report_path, all_lines = load_report(date)
        print("Comparing reports.")
        current_report = compare_reports(date, current_report_path, compared_report)
        print("Reports were compared.")
    
    create_html(report_folder, date, all_lines)   

    
    


if __name__ == "__main__":
    main(sys.argv[1:])


