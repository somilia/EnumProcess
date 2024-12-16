#include "enum_process.h"


BOOL readConfigFile(IN const char* filename, IN char strings[][256], OUT int* count) {
	/* Open the file and count the number of lines if strings is NULL
	* Otherwise, read the file and store the lines in the strings array
	* @param filename : the name of the file to read
	* @param strings : the array of strings to store the lines
	* @param count : the number of lines in the file
	* @return TRUE if the file is read successfully, FALSE otherwise
    */
    FILE* file;
    if (fopen_s(&file, filename, "r") != 0) {
		printf("Error [readConfigFile] : Impossible to open the file %s\n", filename);
        return FALSE;
    }

    char line[256];
    *count = 0;
    if (strings == NULL) {
        while (fgets(line, sizeof(line), file)) {
            (*count)++;
        }
        fclose(file);
        return TRUE;
    }

    while (fgets(line, sizeof(line), file)) {
		line[strcspn(line, "\r\n")] = '\0'; // Remove the newline character
        strcpy_s(strings[*count], sizeof(strings[*count]), line);
        (*count)++;
    }

    fclose(file);
    return TRUE;
}

BOOL PrintProcessMemory(IN DWORD processId, IN const char strings[][256], IN int stringCount, IN SYSTEM_INFO sysInfo, IN int verbose) {
	/* Print the memory of a process and check if it contains the strings
	* @param processId : the ID of the process
	* @param strings : the array of strings to search for
	* @param stringCount : the number of strings
	* @param sysInfo : the system information
	* @param verbose : the verbose mode
	* @return TRUE if the memory is printed successfully, FALSE otherwise
    */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (hProcess == NULL) {
        return FALSE;
    }
   
    MEMORY_BASIC_INFORMATION memInfo;
    unsigned char* address = 0;

    while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo)) == sizeof(memInfo) && address < (PBYTE)sysInfo.lpMaximumApplicationAddress) {

        if (memInfo.State == MEM_COMMIT &&
            ((memInfo.Protect & PAGE_GUARD) == 0) &&
            ((memInfo.Protect & PAGE_NOACCESS) == 0) &&
            ((memInfo.Protect & PAGE_EXECUTE) == 0) &&
            ((memInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) != 0)) {

            wchar_t* buffer = (wchar_t*)malloc(memInfo.RegionSize);
            if (buffer == NULL) {
				printf("Error [PrintProcessMemory] : memory allocation failed.\n");
                break;
            }
            if (!ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, NULL)) {
				printf("Error [PrintProcessMemory] : memory read failed.\n");
                free(buffer);
                continue;
            }
            for (int i = 0; i < stringCount; i++) {
				if (strstr(buffer, strings[i])) {
                    WCHAR szProc[MAX_PATH];
                    printf("\n--------------------------------------------------------------------\n");
					printf("String [%s] found in process %u\n", strings[i], processId);
					if (verbose == 1) {
						printf("BaseAddress : 0x%p, RegionSize : %d octets\n", memInfo.BaseAddress, memInfo.RegionSize);
					}

                    if (!GetModuleFileNameEx(hProcess, NULL, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("Error [PrintProcessMemory] : Cannot get the path of the process %u\n", processId);
                    }
                    else {
                        wprintf(L"PATH : %s\n", szProc);
                    }
                    free(buffer);
                    CloseHandle(hProcess);
                    return 1;
                }
            }
            free(buffer);
        }
        address += memInfo.RegionSize;
    }
    CloseHandle(hProcess);
    return TRUE;
}

BOOL listProcesses(IN const char strings[][256], IN int stringCount, OUT ProcessNode** head, IN int verbose) {
	/* List all running processes and call PrintProcessMemory for each process to check if the memory contains the strings
	* @param strings : the array of strings to search for
	* @param stringCount : the number of strings
	* @param head : the head of the linked list of processes that couldn't be analyzed
	* @param verbose : the verbose mode
	* @return TRUE if the processes are listed successfully, FALSE otherwise
    */
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("Error : CreateToolhelp32Snapshot failed : %d\n", GetLastError());
        return FALSE;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (!PrintProcessMemory(pe32.th32ProcessID, strings, stringCount, sysInfo, verbose)) {
				addProcessNode(head, pe32.th32ProcessID, pe32.szExeFile);
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
	return TRUE;
}

int main(int argc, char* argv[]) {
    int verbose = 0;

    if (!check_options(argv, argc, &verbose)) {
        return 1;
    }
    int stringCount = 0;

	// Count the number of strings in the configuration file
    if (!readConfigFile("chaine.cfg", NULL, &stringCount)) {
		printf("Error : reading the configuration file failed : %d\n", GetLastError());
        return 1;
    }

	// Allocate the right amount of memory for the strings
    char (*strings)[256] = calloc(stringCount, 256);

    if (strings == NULL) {
		printf("Error : memory allocation failed : %d\n", GetLastError());
        return 1;
    }

	// Read the strings from the configuration file
    if (!readConfigFile("chaine.cfg", strings, &stringCount)) {
		printf("Error : reading the configuration file failed : %d\n", GetLastError());
        free(strings);
        return 1;
    }
    ProcessNode* head = NULL;

	if (!listProcesses(strings, stringCount, &head, verbose)) {
		printf("Error : listing processes failed\n");
	}

    free(strings);
	printProcessNodes(head);
	freeProcessNodes(head);
    return 0;
}

void addProcessNode(IN OUT ProcessNode** head, IN DWORD pid, IN wchar_t* name) {
    ProcessNode* new_node = (ProcessNode*)malloc(sizeof(ProcessNode));
    if (!new_node) {
        perror("Error [addProcessNode] : memory allocation failed.");
        exit(EXIT_FAILURE);
    }

    new_node->pid = pid;

	size_t name_len = wcslen(name) + 1;  // +1 for the null-terminator
    new_node->name = (wchar_t*)malloc(name_len * sizeof(wchar_t));
    if (!new_node->name) {
        perror("Error [addProcessNode] : memory allocation failed.");
        free(new_node);
        exit(EXIT_FAILURE);
    }
    wcscpy_s(new_node->name, name_len, name);

    new_node->next = *head;
    *head = new_node;
}

void freeProcessNodes(IN ProcessNode* head) {
    ProcessNode* current = head;
    while (current != NULL) {
        ProcessNode* next = current->next;
        free(current->name);
        free(current);
        current = next;
    }
}
void printProcessNodes(IN ProcessNode* head) {
    ProcessNode* current = head;
    while (current != NULL) {
        printf("[RESULT] Impossible to analyze process %ws (PID : %u)\n", current->name, current->pid);
        current = current->next;
    }
}

BOOL check_options(IN char* argv[], IN int argc, OUT int *verbose) {
    /* Check the command line options
    * @param argv : the array of arguments
    * @param argc : the number of arguments
    * @param verbose : the verbose mode
    * @return TRUE if the options are checked successfully, FALSE otherwise
    */
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-v") == 0) {
                *verbose = 1;
            }
            else {
                if (strcmp(argv[i], "-h") != 0) {
                    printf("Error : unknown option %s\n", argv[i]);
                }
                printf("The program lists the currently running processes on Windows and checks if their memory contains any string from a file named chaine.cfg located next to it.\n");
                printf("Each line corresponds to a complete string to search for in the process's memory.\n");
                printf("The program returns the PID, name, and path of the binary containing the string.\n");
                printf("The program will list the name and PID of processes it couldn't analyze.\n");
                printf("Aide :\n");
                printf("  -v   : Mode verbose\n");
                printf("  -h   : Print this help\n");
                return FALSE;
            }
        }
    }
    return TRUE;
}
