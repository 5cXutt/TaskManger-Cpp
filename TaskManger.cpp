#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>

const std::string ANSI_COLOR_GREEN_CYAN = "\x1b[36m";

std::wstring GetProcessName(DWORD processId) {
    std::wstring processName = L"Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        wchar_t processPath[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH)) {
            std::wstring processPathStr = processPath;
            size_t lastSlash = processPathStr.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos && lastSlash < processPathStr.length() - 1) {
                processName = processPathStr.substr(lastSlash + 1);
            }
        }
        CloseHandle(hProcess);
    }
    return processName;
}

void ListProcesses() {
    std::cout << ANSI_COLOR_GREEN_CYAN;
    std::cout << "Elenco dei processi attivi:" << std::endl;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Errore durante la creazione dello snapshot dei processi." << std::endl;
        return;
    }
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Errore durante il recupero delle informazioni sul primo processo." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }
    std::wstring processNameToPrint;
    do {
        if (std::wstring(pe32.szExeFile) != L"svchost.exe") {
            if (processNameToPrint.empty() || processNameToPrint != pe32.szExeFile) {
                processNameToPrint = pe32.szExeFile;
                std::wcout << L"PID: " << pe32.th32ProcessID << L"\tNome: " << pe32.szExeFile << std::endl;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
}

void PrintProcessInfo(DWORD processId) {
    std::cout << "Informazioni sul processo:" << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Errore durante l'apertura del processo." << std::endl;
        return;
    }
    wchar_t processPath[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH) == 0) {
        std::cerr << "Errore durante il recupero del percorso del file eseguibile." << std::endl;
        CloseHandle(hProcess);
        return;
    }
    std::wcout << L"Percorso del file eseguibile: " << processPath << std::endl;
    std::wstring processDirectory = processPath;
    size_t lastSlash = processDirectory.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        processDirectory = processDirectory.substr(0, lastSlash);
        std::wcout << L"Directory del file eseguibile: " << processDirectory << std::endl;
    }
    else {
        std::cerr << "Impossibile ottenere la directory del file eseguibile." << std::endl;
    }
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        std::cout << "Memoria utilizzata dal processo: " << pmc.PrivateUsage / 1024 << " KB" << std::endl;
    }
    else {
        std::cerr << "Impossibile ottenere l'utilizzo della memoria del processo." << std::endl;
    }
    CloseHandle(hProcess);
}

DWORD GetMainProcessId(DWORD processId) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Errore durante la creazione dello snapshot dei processi." << std::endl;
        return 0;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == processId) {
                CloseHandle(hSnapshot);
                return pe32.th32ParentProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

bool TerminateProcessById(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Errore durante l'apertura del processo." << std::endl;
        return false;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Errore durante la terminazione del processo." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Processo terminato con successo." << std::endl;
    CloseHandle(hProcess);
    return true;
}

bool TerminateMainProcess(DWORD processId) {
    DWORD mainProcessId = GetMainProcessId(processId);
    if (mainProcessId == 0) {
        std::cerr << "Impossibile ottenere l'ID del processo principale." << std::endl;
        return false;
    }

    std::cout << "Processo principale: " << mainProcessId << std::endl;

    return TerminateProcessById(mainProcessId);
}

void PrintMemoryRegions(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Errore durante l'apertura del processo." << std::endl;
        return;
    }

    MEMORY_BASIC_INFORMATION memInfo;
    LPVOID lpAddress = NULL;

    while (VirtualQueryEx(hProcess, lpAddress, &memInfo, sizeof(memInfo)) != 0) {
        std::cout << "Base Address: " << memInfo.BaseAddress << std::endl;
        std::cout << "Size: " << memInfo.RegionSize << std::endl;
        std::cout << "Allocation Protect: " << memInfo.AllocationProtect << std::endl;
        std::cout << "State: " << memInfo.State << std::endl;
        std::cout << "Type: " << memInfo.Type << std::endl << std::endl;
        lpAddress = (LPVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
    }

    CloseHandle(hProcess);
}

void PrintDLLInfo(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Errore durante l'apertura del processo." << std::endl;
        return;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                std::wcout << szModName << std::endl;
            }
        }
    }
    else {
        std::cerr << "Impossibile ottenere le informazioni sulle DLL caricate." << std::endl;
    }
    CloseHandle(hProcess);
}

void PrintCPUUsage(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Errore durante l'apertura del processo." << std::endl;
        return;
    }
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER kernelTimeInt, userTimeInt;
        kernelTimeInt.LowPart = kernelTime.dwLowDateTime;
        kernelTimeInt.HighPart = kernelTime.dwHighDateTime;

        userTimeInt.LowPart = userTime.dwLowDateTime;
        userTimeInt.HighPart = userTime.dwHighDateTime;

        ULONGLONG totalCpuTime = kernelTimeInt.QuadPart + userTimeInt.QuadPart;
        std::cout << "Utilizzo della CPU: " << totalCpuTime << " 100 ns ticks" << std::endl;
    }
    else {
        std::cerr << "Impossibile ottenere le informazioni sull'utilizzo della CPU del processo." << std::endl;
    }
    CloseHandle(hProcess);
}

int main() {
    while (true) {
        system("cls");
        ListProcesses();
        DWORD processId;
        std::cout << "Inserisci l'ID del processo da analizzare (0 per uscire): ";
        std::cin >> processId;
        if (processId == 0) {
            break;
        }
        PrintProcessInfo(processId);
        char choice;
        std::cout << "Vuoi stampare le informazioni sulle regioni di memoria allocate? (s/n): ";
        std::cin >> choice;
        if (choice == 's' || choice == 'S') {
            PrintMemoryRegions(processId);
        }
        std::cout << "Vuoi stampare le informazioni sulle DLL caricate? (s/n): ";
        std::cin >> choice;
        if (choice == 's' || choice == 'S') {
            PrintDLLInfo(processId);
        }
        std::cout << "Vuoi stampare le informazioni sull'utilizzo della CPU? (s/n): ";
        std::cin >> choice;
        if (choice == 's' || choice == 'S') {
            PrintCPUUsage(processId);
        }
        std::cout << "Vuoi terminare il processo principale? (s/n): ";
        std::cin >> choice;
        if (choice == 's' || choice == 'S') {
            if (TerminateMainProcess(processId)) {
                std::cout << "Il processo principale è stato terminato con successo." << std::endl;
            }
            else {
                std::cerr << "Si è verificato un errore durante la terminazione del processo principale." << std::endl;
            }
        }
    }
    return 0;
}
