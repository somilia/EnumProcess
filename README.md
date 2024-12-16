
# Process Enumeration

The program lists the currently running processes on Windows and checks if their memory contains any string from a file named chaine.cfg.
Each line corresponds to a complete string to search for in the process's memory.
The program returns the PID, name, and path of the binary containing the string.
The program will list the name and PID of processes it couldn't analyze.

### Help:
 -v   : Verbose mode (level 1)
 
 -h   : Display this help

