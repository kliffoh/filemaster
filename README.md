Filemaster: Your Cybersecurity Utility 🛡️

This single-script tool, designed by Clive Otieno, offers practical demonstrations of key cybersecurity concepts and file management.

What It Does (The Mechanisms)

Defensive Hashing: Secures data (like passwords) by converting them into an unreadable, non-reversible code using SHA-256.

Input Sanitization: Cleans user input to neutralize dangerous characters (e.g., < and >), preventing injection attacks like XSS.

Log File Manager (File I/O): Reads a source file, calculates its integrity hash, standardizes the text (to uppercase), and writes the clean content to a new destination file. This includes robust error handling for missing files.

How to Use It

Run the Script: Start the program by running the Python file:

python filemaster.py


Select an Option: When prompted, enter the number (1, 2, or 3) for the function you want to use.

Example: Enter 3 to start the Log File Manager, then follow the prompts for the source and destination file paths.

Exit: Type exit or quit at any time to close the utility.
