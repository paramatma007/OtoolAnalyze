# Tools

Hey Everyone! Welcome to my Tools repo. This is where I'll be sharing scripts that I have developed to solve some common problems in the cyber security world. Note that each of these scripts serve a specific purpose and is intended to make it easier for cyber security professionals to perform their work.

## otool_analyze

This script is developed to help us perform Reverse Engineering of an iOS application, specifically in static analysis of an IPA file for detecting common security misconfigurations. We can complete a small portion of a very complex area in Cyber Security through this script - iOS Application Penetration Testing.

### Dependencies

* otool
* python3
* MacOS
* iOS Application's IPA file

### Preparation and Execution

* The script can be downloaded directly and should work as long as above dependencies have been taken care of. Rename the iPA file from '.ipa' extension to '.zip' and extract the app folder.
* File path of the iOS app's Mach-O binary is required as input. This file is located within the iOS application binary (.app directory) and would have the same name as the app itself.
* Script can be run as follows.
```
./otool_analyze.py
```
* Ensure that any names of files/directories with spaces are enclosed in single quotes.

### License

This project is licensed under the Apache 2.0 License - see the LICENSE.md file for details
