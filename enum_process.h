#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>


// Structure for a process node
struct ProcessNode {
    DWORD pid;
    wchar_t* name;
    struct ProcessNode* next;
}; typedef struct ProcessNode ProcessNode;


void addProcessNode(IN OUT ProcessNode** head, IN DWORD pid, IN wchar_t* name);
void freeProcessNodes(IN ProcessNode* head);
void printProcessNodes(IN ProcessNode* head);
BOOL readConfigFile(IN const char* filename, IN char strings[][256], OUT int* count);
BOOL PrintProcessMemory(IN DWORD processId, IN const char strings[][256], IN int stringCount, IN SYSTEM_INFO sysInfo, IN int verbose);
BOOL listProcesses(IN const char strings[][256], IN int stringCount, OUT ProcessNode** head, IN int verbose);
BOOL check_options(IN char* argv[], IN int argc, OUT int *verbose);
