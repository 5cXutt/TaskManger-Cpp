# ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=22&pause=1000&color=1BDBF7&random=false&width=435&lines=Simple+TaskManger+in+Cpp)

### This C++ program is designed to list active processes on a Windows system, allowing the user to view detailed information about each process and terminate a selected process if necessary.

## Dependencies
The program depends on the following libraries:

- `<iostream>`: for standard input/output
- `<windows.h>`: for accessing Windows APIs
- `<tlhelp32.h>`: for enumerating processes
- `<psapi.h>`: for getting information about process memory
- `<string>`: for string handling
- `<cstdlib>`: for using the `system()` function for screen clearing

## Main Functions

- **`GetProcessName(DWORD processId)`:** Returns the name of the process given its ID.
- **`ListProcesses()`:** Lists all active processes, excluding "svchost.exe".
- **`PrintProcessInfo(DWORD processId)`:** Prints detailed information about a specified process.
- **`TerminateProcessById(DWORD processId)`:** Terminates a process given its ID.
- **`PrintMemoryRegions(DWORD processId)`:** Prints information about memory regions allocated for a process.
- **`PrintDLLInfo(DWORD processId)`:** Prints information about DLLs loaded by a process.
- **`PrintCPUUsage(DWORD processId)`:** Prints information about CPU usage by a process.

## `main()` Function
- A while loop continues to run the program until the user chooses to exit by entering `0` as the process ID.
- At startup, all active processes are listed.
- The user can input the ID of a process to view detailed information about it.
- After viewing the information, the user can choose to print information about memory, loaded DLLs, and CPU usage of the process.
- The user can also choose to terminate the process.
- The loop continues until the user chooses to exit.

![My Skills](https://skillicons.dev/icons?i=windows,visualstudio,cpp,github,git)


# [![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=16&pause=1000&color=F752D7&random=false&width=435&lines=%F0%9F%92%96+Support+the+Project+%F0%9F%92%96)](https://buymeacoffee.com/scuttlang)

