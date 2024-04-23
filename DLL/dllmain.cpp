#include "pch.h"
#include "stdio.h"
#include "windows.h"
#include "tchar.h"
#include <stdint.h>

#pragma pack(push,1)

using namespace std;

uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

struct GOGO_NAM
{
    SHORT opcode1;
    DWORD64 lpTarget1;
    SHORT opcode2;
};


#pragma pack(pop)

BOOL WINAPI UnHook();
BOOL WINAPI Hook();
DWORD64 OrgFunc;

INT WINAPI fakeWriteFile(HANDLE hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped) {
    MessageBoxA(NULL, (LPCSTR)lpBuffer, "hooking api call sucess", MB_OK);

    UnHook();
    BOOL ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    Hook();
    return ret;
}

GOGO_NAM orgFP;
BOOL Hooked = FALSE;

BOOL WINAPI UnHook() {
    if (!Hooked) return 0;
    GOGO_NAM WriteFIleorg;
    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL) {
        OutputDebugString(L"UnHook GetProcAddress error");
        return -1;
    }

    if (*(SHORT*)lpOrgFunc == 0xB848) {
        if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "WriteFile")) == NULL)
            OutputDebugString(L"UnHook GetProcAddress error");
        return -1;
    }

    DWORD dwOldProtect;
    if (VirtualProtect(lpOrgFunc, sizeof(GOGO_NAM), PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL) {
        OutputDebugString(L"UnHook VirtualProtect error");
        return -1;
    }
    memcpy_s(lpOrgFunc, sizeof(DWORD64), &OrgFunc, sizeof(DWORD64));

    VirtualProtect(lpOrgFunc, sizeof(GOGO_NAM), dwOldProtect, NULL);
    Hooked = FALSE;
    return 0;

}

BOOL WINAPI Hook() {
    if (Hooked) return 0;
    char error_code[90000];
    char lpOrgFunc_t[256];
    char lpOrgFunc_t2[256];
    char fakeWriteFile_p[256];

    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
    {
        MessageBoxA(NULL, "Hook", "kernel32 Hook faild!", MB_OK);
        return -1;
    }


    if (*(SHORT*)lpOrgFunc == 0xB848) {
        if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "WriteFile")) == NULL)
        {
            MessageBoxA(NULL, "Hook", "kernelbase Hook faild!", MB_OK);
            return -1;

        }
    }

    DWORD dwOldProtect;
    DWORD dwOldProtect2;


    if (VirtualProtect(lpOrgFunc, sizeof(GOGO_NAM), PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL) {
        return -1;
    }
    printf("%d\n", dwOldProtect);
    memcpy_s(&OrgFunc, sizeof(DWORD64), lpOrgFunc, sizeof(DWORD64));

    GOGO_NAM newFuncObj;

    newFuncObj.opcode1 = 0xB848;
    newFuncObj.lpTarget1 = (DWORD64)(fakeWriteFile);
    newFuncObj.opcode2 = 0xe0ff;




    memcpy_s(lpOrgFunc, sizeof(GOGO_NAM), &newFuncObj, sizeof(GOGO_NAM));


    if (VirtualProtect(lpOrgFunc, sizeof(GOGO_NAM), dwOldProtect, &dwOldProtect2) == NULL) {
        return -1;
    }
    Hooked = TRUE;
    return 0;

}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        Hook();
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}