import csv
import json


# Obtaining the package list from the 22-packages.csv
# source link : https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
# A sample of a few rows in the 22-packages.csv, to display the structure  
#╭───────────┬─────────────────────┬────────────┬─────────┬──────────────────────────┬──────────────────────────╮
#│ Ecosystem │ Namespace           │ Name       │ Version │ Published                │ Detected                 │
#├───────────┼─────────────────────┼────────────┼─────────┼──────────────────────────┼──────────────────────────┤
#│ pypi      │ —                   │ mistralai  │ 2.4.6   │ 2026-05-12T00:05:16.616Z │ 2026-05-12T03:05:38.635Z │
#│ pypi      │ —                   │ mistralai  │ 2.4.6   │ 2026-05-12T00:05:16.616Z │ 2026-05-12T03:05:17.887Z │

with open("22-packages.csv", "r") as csvfile:
    csvreader = csv.reader(csvfile)
    shai_hulud_packages = []
    for row in csvreader:
        if row[0] == "Ecosystem" or row[0] != "npm":
            continue
        shai_hulud_packages.append(row)

# This dictionary is for storing the affected package details such as 
# name and version for the packages that are in the npm ecosystem
shai_hulud_packages_org_dict = {}

# Obtaining the org list, the namespaces in the npm ecosystem affected by the mini shai hulud 
distinct_org_list = []

for package_details in shai_hulud_packages:
    if package_details[1] not in distinct_org_list:
        distinct_org_list.append(package_details[1])

# Preparing the dictionary
for org in distinct_org_list:
    shai_hulud_packages_org_dict[org] = []

# Storing the package name and version in the prepared dictionary.
for org in distinct_org_list:
    for package in shai_hulud_packages:
        if package[1] == org:
            shai_hulud_packages_org_dict[org].append({ "name" : package[2], "version" : package[3] })

# Preparing a list object to store the yara strings
yara_rule_strings = []

count=1
for org in shai_hulud_packages_org_dict.keys():
    for package_details in shai_hulud_packages_org_dict[org]:
        yara_rule_strings.append("$n"+str(count)+"=  /(\\s)*\"("+org+"\/)*"+package_details["name"]+"\":(\\s)*\"(\^|~)*"+package_details["version"]+"\"(\\s)*/")
        count+=1

# Writing the prepared yara variables into a text file
with open("yara_strings_variables.txt","w") as txtfile:
    txtfile.write("\n\n")
    for yara_rule in yara_rule_strings:
        txtfile.write("\t\t\t\t"+yara_rule+"\n")
