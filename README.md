# Mini Shai Hulud YARA Rule 


This repo is for the yara rules that I am writing, for helping detect the npm packages affected by the **Mini Shai Hulud** Supply Chain attack that list the compromised packages in their `package.json`. The threat actor identified is **TeamPCP**.

### Data Source

This `CSV` can be found in the socket.dev link provided in the References section of this README. 

`head -n 5 22-packages.csv | tennis`

![The CSV Structure of 22-packages.csv file that contains package details](Images/22_packages_csv_structure.png)

## Preparing the YARA Rule

The package details for the npm ecosystem were parsed and extracted from the csv, as shown in the below image, on the python3 REPL interface.
![Using the python3 interpreter for data munging tasks](Images/python3_REPL_code.png)




# References
- https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
