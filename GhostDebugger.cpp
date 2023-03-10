#include <windows.h>
#include <tlhelp32.h>
#include <debugapi.h>
#include <dbghelp.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <fileapi.h>
#pragma comment(lib, "dbghelp.lib")

using namespace std;


int Find_Process(const wchar_t*);
int Adjust_Token_Privileges();
void Print_Adjust_Token_Privileges();
int Active_Debug_Mode(DWORD);
int Create_Process_For_debugging(const wchar_t*);
void Get_THreadContext(HANDLE);
void PrintStackTrace(HANDLE, HANDLE);
void GetprocessInfo(DEBUG_EVENT);
HANDLE Get_Debugg_Events();
void PrintDLL_Info(HANDLE);


int Find_Process(const wchar_t* processname) {

    char str[100]; // Multi-byte character string
    int len = WideCharToMultiByte(CP_UTF8, 0, processname, -1, str, 100, nullptr, nullptr); // Convert to multi-byte
    if (len > 0) {
        printf("\nHunting the Process: %s\n", str); // Print the multi-byte string
    }

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot() failed\n";
        return 0;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            // Compare process name with the one we are looking for
            if (_wcsicmp(pe32.szExeFile, processname) == 0) {
                std::cout << "Process PID: " << pe32.th32ProcessID << '\n';
                char str[100]; // Multi-byte character string
                int len = WideCharToMultiByte(CP_UTF8, 0, processname, -1, str, 100, nullptr, nullptr); // Convert to multi-byte
                if (len > 0) {
                    printf("Process Name:: %s\n", str); // Print the multi-byte string
                }
                DWORD processId = pe32.th32ProcessID;
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
                if (hProcess == NULL) {
                    std::cerr << "Error: OpenProcess() failed\n";
                    std::cout << "Error Code:" << GetLastError() << '\n';
                }
                else
                {
                    std::cerr << "Success Open the Process: " << hProcess << "\n";
                    return pe32.th32ProcessID;
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));

        return 0;
    }
}

int Adjust_Token_Privileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Error: OpenProcessToken() failed\n";
        return 1;
    }
    //Lookup the LUID for the SeDebugPrivilege privilege
    LUID SE_DEBUG_LUID;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &SE_DEBUG_LUID)) {
        std::cerr << "Error: LookupPrivilegeValue() failed\n";
        return 1;
    }
    // Enable the SeDebugPrivilege privilege for the current process
    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = SE_DEBUG_LUID;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "Error: AdjustTokenPrivileges() failed\n";
        return 1;
    }
    std::cout << "SeDebugPrivilege enabled" << std::endl;
    CloseHandle(hToken);
    return 0;
}

void Print_Adjust_Token_Privileges() {
    printf("Print all The curent privilage\n");
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Error: OpenProcessToken() failed\n";
        return;
    }

    // Get the size of the token information buffer
    DWORD dwTokenInfoLen;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwTokenInfoLen)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "Error: GetTokenInformation() failed\n";
            return;
        }
    }

    // Allocate the token information buffer and retrieve the token information
    PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwTokenInfoLen);
    if (!pTokenPrivileges) {
        std::cerr << "Error: Failed to allocate memory for token information\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenInfoLen, &dwTokenInfoLen)) {
        std::cerr << "Error: GetTokenInformation() failed\n";
        free(pTokenPrivileges);
        return;
    }

    // Iterate through the list of privileges and print their names
    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        LUID Luid = pTokenPrivileges->Privileges[i].Luid;
        DWORD dwNameLen = 0;
        LookupPrivilegeName(NULL, &Luid, NULL, &dwNameLen);
        std::wstring privilegeName(dwNameLen, L'\0');
        if (LookupPrivilegeName(NULL, &Luid, &privilegeName[0], &dwNameLen)) {
            std::wcout << privilegeName << '\n';
        }
    }
    printf("\n========================================================\n");
    free(pTokenPrivileges);
    CloseHandle(hToken);

}

int Active_Debug_Mode(DWORD processId) {

    if (DebugActiveProcess(processId)) {
        std::cerr << "\nSuccess to Active Debug Mode on process: " << processId << "\n";
        return 1;
    }
    else
    {
        printf("\nError Failed to Active Debug Mode on process: %d\n", GetLastError());
        return 0;

    }
    
}

int Create_Process_For_debugging(const wchar_t* processname) {

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // Set up the PROCESS_INFORMATION structure
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Create the process with DEBUG_PROCESS flag
    if (!CreateProcess(NULL, (LPWSTR)processname, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        
        std::cout << "Failed to create process. Error code: " << GetLastError() << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cout << "\nProcess created successfully Process ID: " << pi.dwProcessId << std::endl;
    }
    return pi.dwProcessId;
}

void Get_THreadContext(HANDLE hThread) {

    HANDLE hProcess = GetCurrentProcess();
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_FULL;


    if (!GetThreadContext(hThread, &threadContext)) {
        std::cerr << "Failed to get thread context: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return;
    }

    DWORD64 Thread_ContextFlags = threadContext.ContextFlags;
    DWORD64 Thread_DebugControl = threadContext.DebugControl;

    DWORD64 rip = threadContext.Rip;
    printf("The rip value is: %llu\n", rip);

    PrintStackTrace(hThread, hProcess);
    //
    // Segment Registers and processor flags.
    //
    //DWORD Thread_EFlags = threadContext.EFlags;
    //printf("The Thread_EFlags value is: %l\n", Thread_EFlags);
    //
    // Program counter.
    //

    //
    // Integer registers.
    //
    //DWORD64 rax = threadContext.Rax;
    //DWORD64 rbx = threadContext.Rbx;
    //DWORD64 rcx = threadContext.Rcx;
    //DWORD64 rdx = threadContext.Rdx;
    //DWORD64 rsp = threadContext.Rsp;
    //DWORD64 rbp = threadContext.Rbp;
    //DWORD64 rsi = threadContext.Rsi;
    //DWORD64 rdi = threadContext.Rdi;
    //
    //printf("The rax value is: %llu\n", rax);
    //printf("The rbx value is: %llu\n", rbx);
    //printf("The rcx value is: %llu\n", rcx);
    //printf("The rdx value is: %llu\n", rdx);
    //printf("The rsp value is: %llu\n", rsp);
    //printf("The rbp value is: %llu\n", rbp);
    //printf("The rdi value is: %llu\n", rdi);
    //printf("The rsi value is: %llu\n", rsi);
    //
    // Debug registers
    //
    //DWORD64 dr0 = threadContext.Dr0;
    //DWORD64 de1 = threadContext.Dr1;
    //DWORD64 dr3 = threadContext.Dr3;
    //DWORD64 dr6 = threadContext.Dr6;
    //DWORD64 dr7 = threadContext.Dr7;
    //
    //printf("The dr0 value is: %llu\n", dr0);
    //printf("The de1 value is: %llu\n", de1);
    //printf("The dr3 value is: %llu\n", dr3);
    //printf("The dr6 value is: %llu\n", dr6);
    //printf("The dr7 value is: %llu\n", dr7);

}

void PrintStackTrace(HANDLE hThread, HANDLE hProcess) {
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(hThread, &ctx))
    {
        std::cerr << "GetThreadContext sucsesed: " << std::endl;
        // store information about a single stack frame in a call stack.
        STACKFRAME64 stackFrame;

        memset(&stackFrame, 0, sizeof(STACKFRAME64));

        //The architecture type of the computer for which the stack trace is generated. 
        #ifdef _M_IX86
                DWORD machineType = IMAGE_FILE_MACHINE_I386;
                stackFrame.AddrPC.Offset = ctx.Eip;
                stackFrame.AddrPC.Mode = AddrModeFlat;
                stackFrame.AddrFrame.Offset = ctx.Ebp;
                stackFrame.AddrFrame.Mode = AddrModeFlat;
                stackFrame.AddrStack.Offset = ctx.Esp;
                stackFrame.AddrStack.Mode = AddrModeFlat;
        #elif _M_X64
                DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
                stackFrame.AddrPC.Offset = ctx.Rip;
                stackFrame.AddrPC.Mode = AddrModeFlat;
                stackFrame.AddrFrame.Offset = ctx.Rsp;
                stackFrame.AddrFrame.Mode = AddrModeFlat;
                stackFrame.AddrStack.Offset = ctx.Rsp;
                stackFrame.AddrStack.Mode = AddrModeFlat;
        #else
        #error "This platform is not supported."
        #endif
        //used to retrieve the call stack of a specified thread. 

        while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &ctx, NULL, NULL, NULL, NULL))
        {

            // addrPC == EIP
            // addrReturn == ESP
            // addrFrame == EBP
            std::cout << "0x" << std::hex << stackFrame.AddrPC.Offset << std::endl;

            if (stackFrame.AddrReturn.Offset == 0)
                break;
        }
    }
    else
    {
        std::cerr << "GetThreadContext failed, error code: " << GetLastError() << std::endl;
    }


}
void PrintDLL_Info(HANDLE hDll) {

    char buffer[MAX_PATH];
    GetFinalPathNameByHandleA(hDll, buffer, MAX_PATH, FILE_NAME_NORMALIZED);

    std::cout << "Final path name: " << buffer << std::endl;
}


void GetprocessInfo(DEBUG_EVENT debugEvent) {

    CREATE_PROCESS_DEBUG_INFO& createProcess = debugEvent.u.CreateProcessInfo;
    // get process dbug information via CREATE_PROCESS_DEBUG_INFO
            // Print some basic information about the event

    DWORD Debug_Event_code = debugEvent.dwDebugEventCode;

    switch (debugEvent.dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:

        std::cout << "\nAn exception has occurred in the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case CREATE_THREAD_DEBUG_EVENT:
        std::cout << "\nA new thread has been created in the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID:" << debugEvent.dwThreadId << std::endl;
        break;

    case CREATE_PROCESS_DEBUG_EVENT:
        std::cout << "\nA new process has been created." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case EXIT_THREAD_DEBUG_EVENT:
        std::cout << "\nA thread has exited in the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case EXIT_PROCESS_DEBUG_EVENT:
        std::cout << "\nThe debugged process has exited." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case LOAD_DLL_DEBUG_EVENT:
        std::cout << "\nA DLL has been loaded in the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        _LOAD_DLL_DEBUG_INFO processDLLInfo = debugEvent.u.LoadDll;

        PrintDLL_Info(processDLLInfo.hFile);

        printf("Handle to the load dll: %p\n", processDLLInfo.hFile);
        printf("Pointer to the base address of the DLL: %lp\n", processDLLInfo.lpBaseOfDll);
        printf("Pointer to the Name of the DLL: %lp\n", (char*)processDLLInfo.lpImageName);
        printf("Pointer to the Name of the DLL: %hu\n", processDLLInfo.fUnicode);

        break;

    case UNLOAD_DLL_DEBUG_EVENT:
        std::cout << "\nA DLL has been unloaded from the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case OUTPUT_DEBUG_STRING_EVENT:
        std::cout << "\nThe debugged process has output a debug string." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    case RIP_EVENT:
        std::cout << "\nA system-defined event has occurred in the debugged process." << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;

    default:
        std::cerr << "\nUnknown debug event code: " << debugEvent.dwDebugEventCode << "\tEvent code: " << debugEvent.dwDebugEventCode << std::endl;
        std::cout << "Process ID: " << debugEvent.dwProcessId << std::endl;
        std::cout << "Thread ID: " << debugEvent.dwThreadId << std::endl;
        break;
    }

    ////A handle to the executable file that started the process.
    //HANDLE processFile = createProcess.hFile;
    //printf("Handle to the executable file: %p\n", processFile);
    ////A handle to the newly created process.
    //HANDLE processHandle = createProcess.hProcess;
    //printf("Handle to the created process: %p\n", processHandle);
    ////A handle to the primary thread of the new process.
    //HANDLE processThread = createProcess.hThread;
    //printf("Handle to the primary thread: %p\n", processThread);
    ////A pointer to the base address of the executable file in memory.
    //LPVOID baseAddress = createProcess.lpBaseOfImage;
    //printf("Pointer to the base address of the executable file in memory: %lp\n", baseAddress);
    ////The offset of the debug information in the executable file
    //DWORD debuginfo_Fileoffset = createProcess.dwDebugInfoFileOffset;
    //printf("offset of the debug information: %ld\n", debuginfo_Fileoffset);
    ////The size of the debug information.
    //DWORD debugInfo_Size = createProcess.nDebugInfoSize;
    //printf("size of the debug information: %ld\n", debugInfo_Size);
    ////A pointer to the thread local storage (TLS) array for the primary thread.
    //LPVOID process_Thread_local_base = createProcess.lpThreadLocalBase;
    //printf("pointer to the thread local storage: %lp\n", process_Thread_local_base);
    ////A pointer to the entry point function of the primary thread.
    //LPVOID process_ImageName = createProcess.lpImageName;
    //printf("pointer to the Process Image Name: %s\n", &process_ImageName);
    //WORD process_Unicode = createProcess.fUnicode;
    //if (process_Unicode) {
    //    printf("Image name: %ls\n", static_cast<wchar_t*>(process_ImageName));
    //}
    //else {
    //    printf("Image name: %s\n", static_cast<char*>(process_ImageName));
    //}
}

HANDLE Get_Debugg_Events() {
    printf("\n======================Events========================\n");
    
    DEBUG_EVENT debugEvent;
    CREATE_THREAD_DEBUG_INFO& createThreadprocess = debugEvent.u.CreateThread;


    while (WaitForDebugEvent(&debugEvent, INFINITE)) {

        // get thread dbug information via CREATE_THREAD_DEBUG_INFO

        GetprocessInfo(debugEvent);

        HANDLE ProcessThread_Handle = createThreadprocess.hThread;
        LPVOID processThreadLocalBase = createThreadprocess.lpStartAddress;

        Get_THreadContext(ProcessThread_Handle);

        // Continue the debugging event
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);

        printf("\n==================================================\n");
    }


    return debugEvent.u.CreateProcessInfo.hProcess;
}

int main()
{
    //UINT codePage = GetACP();
    //SetConsoleOutputCP(codePage);
    //SetConsoleOutputCP(CP_);
    //Print_Adjust_Token_Privileges();
    //Adjust SeDebugPrivilege privilege
    Adjust_Token_Privileges();

   //printf("\n=================Attached Process=================\n");
   //WCHAR Attached_Process[] = L"cmd.exe";
   //DWORD processId = Find_Process(Attached_Process);
   //if (processId) {
   //    if(Active_Debug_Mode(processId))
   //
   //        CloseHandle(Get_Debugg_Events());
   //}
   //
    printf("\n=====================New Process==================\n");

    //WCHAR Open_Process[] = L"C:\\createThread.exe";
    WCHAR Open_Process[] = L"C:\\Windows\\System32\\cmd.exe";
    //Print_Adjust_Token_Privileges();
    DWORD Created_processId = Create_Process_For_debugging(Open_Process);
    if (Created_processId) {
        if(Active_Debug_Mode(Created_processId))

            CloseHandle(Get_Debugg_Events());
            CloseHandle(Get_Debugg_Events());
    }

    printf("\n==================================================\n");
    
    return 0;
}
