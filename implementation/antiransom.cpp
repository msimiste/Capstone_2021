/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* Hook and trampoline into the MS Crypto API - Replaces Real_Crypt* with Fake_Crypt*
* Record calls, and trampoline back to the real functions.
* Recorded calls are logged in `C:\CryptoHookLog.dll`
*
***************************************************************************************************/

#include <stdio.h>
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
#include "detours/detours.h"
#include <tchar.h>
#include "antiransom.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")

static DWORD g_dwKeyBlobLen_Exfil = 0;
static PBYTE g_pbKeyBlob_Exfil = NULL;
static BOOL recursive = FALSE;
static BOOL recursive2 = FALSE;

// Works for Crypto++563-Debug
const DWORD NEEDLE_SIZE = 32;
char NEEDLE[NEEDLE_SIZE] = {0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x24, 0x89, 0x4D, 0xF4, 0x8B, 0x45, 0xF4, 0x8B, 0x55, 0x0C,
                            0x89, 0x14, 0x24, 0x89, 0xC1, 0xE8, 0x8A, 0x02, 0x00, 0x00, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x00};

/* This is a hack to not find the needle in this DLL's memory */
int dudd1 = 0x123123;
int dudd2 = 0x123123;
int dudd3 = 0x123123;
int dudd4 = 0x123123;
char NEEDLE_END = 0xF4;

/***********************************************************************************************/
/* Our trampoline functions */
/***********************************************************************************************/
BOOL WINAPI Fake_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime(); 
    BOOL ret = Real_CryptGenRandom(hProv, dwLen, pbBuffer);
	BOOL correctSize = dwLen == 16;
	if(correctSize){		
		fprintf(fd, "\t RandomData = ");
		for (int i = 0 ; i < dwLen ; i++) {
			fprintf(fd, "%02x",pbBuffer[i]);
		}
		fprintf(fd, "\n");
	}
    fclose(fd);
    return ret;
}

NTSTATUS WINAPI Fake_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
  ULONG EaLength) {
    if (recursive2 == FALSE) {
        recursive2 = TRUE;
        PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
        std::wstring temp1(FileName->Buffer, FileName->Length / sizeof(wchar_t));
        std::string temp(temp1.begin(),temp1.end());
		int contains = temp.find(".WNCRY");
        if(contains >=0){
            FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
            std::string mytime = CurrentTime();
            fprintf(fd, "[NtCreateFile] %s\t", mytime.c_str());
            PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
            fprintf(fd, "\t FileName = %wZ\t", FileName);
            fclose(fd);
    
			if (Real_HookedSig == NULL) {
				unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
				if (sig_address != NULL) {
					Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
					DetourTransactionBegin();
					DetourUpdateThread(GetCurrentThread());
					DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
					DetourTransactionCommit();
				}
			}			
		}
        recursive2 = FALSE;
    }
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

VOID __fastcall Fake_HookedSig(void * This, void * throwaway, const BYTE* key, size_t length, DWORD* whatever) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    fprintf(fd, "\t CryptoPPKey = ");
    for (int i = 0 ; i < length ; i++) {
        fprintf(fd, "%02x",key[i]);
    }
    fprintf(fd, "\n");
    fclose(fd);
    return Real_HookedSig(This, key, length, whatever);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");

    switch(Reason) {
    case DLL_PROCESS_ATTACH:
        // DetourRestoreAfterWith(); // eugenek: not sure if this is necessary
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());    
        DetourAttach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);       
        DetourAttach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);     

        DetourTransactionCommit();
        
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());      
        DetourDetach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);
        DetourDetach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);   
        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    fclose(fd);
    return TRUE;
}


/*
* Searches the virtual memory of the process for a byte signature.
* Input:
*   sig - the signature to search for
*   sigend - the end of the signature to search for
*   sigsize - the size of the signature to search for
* Output:
*   virtual memory address of the byte signature if found. NULL if not found */
unsigned char* search_memory(char* sig, char sigend, size_t sigsize) {
    unsigned char* sig_address = NULL;
    /* Get our PID and a handle to the process */
    DWORD pid = GetCurrentProcessId();
    HANDLE process = OpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, FALSE, pid);

    /* Intelligently iterate over only mapped executable pages and dump them */
    /* Search for the signature in the pages */
    MEMORY_BASIC_INFORMATION info;
    DWORD bytesRead = 0;
    char* pbuf = NULL;
    unsigned char* current = NULL;
    for (current = NULL; VirtualQueryEx(process, current, &info, sizeof(info)) == sizeof(info); current += info.RegionSize) {
        // Only iterate over mapped executable memory
        if (info.State == MEM_COMMIT && (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE || info.Type == MEM_IMAGE) &&
            (info.AllocationProtect == PAGE_EXECUTE || info.AllocationProtect == PAGE_EXECUTE_READ
                || info.AllocationProtect == PAGE_EXECUTE_READWRITE || info.AllocationProtect == PAGE_EXECUTE_WRITECOPY)) {

            pbuf = (char*)malloc(info.RegionSize);
            ReadProcessMemory(process, current, pbuf, info.RegionSize, &bytesRead);
            size_t match_offset = search_array(sig, sigend, sigsize, pbuf, bytesRead, 31); // 80% match
            if (match_offset != NULL) {
                sig_address = current+match_offset;
                break;

            }

        }
    }

    return sig_address;
}

/*
* Searches an array for a fuzzy subarray.
* Input:
*   needle - subarray to search for
*   needle_end - last part of the subarray to search for
*   needleSize - size of aubarray to search for
*   haystack - array to search in
*   haystackSize - size of array to search in
*   threshold - integer amount of bytes that much match to return a match
* Output:
*   offset to the first match (only aim for one!). If none, then NULL. */
size_t search_array(char *needle, char needle_end, size_t needleSize, char *haystack, size_t haystackSize, size_t threshold) {
    size_t match_offset = NULL;
    for (int i = 0; i + needleSize <= haystackSize; i++) {
        size_t match_count = 0;
        for (int j = 0; j < needleSize; j++) {
            char needle_compare = needle[j];
            /* This is a hack to not find the needle in this DLL's memory */
            if (j == needleSize - 1) {
                needle_compare = needle_end;
            }
            if (haystack[i+j] == needle_compare) {
                match_count++;
            }
        }

        if(match_count >= threshold) {
            match_offset = i;
            break;
        }
    }

    return match_offset;
}

const std::string CurrentTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char currentTime[100] = "";
    sprintf(currentTime,"%d:%d:%d %d",st.wHour, st.wMinute, st.wSecond , st.wMilliseconds);
    return std::string(currentTime);
}

void MyHandleError(LPTSTR psz, int nErrorNumber) {
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}

