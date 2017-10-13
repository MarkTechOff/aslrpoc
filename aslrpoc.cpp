// aslrpoc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define ENVIRONMENT_VAR  _T("ASLRPOC")



// Heuristic function to guess a safe place to map the memory.
LPVOID GuessSafeAddress(DWORD size)
{
	// duplicate what ES does - see dfhcpipc.cpy in ES code.
	SYSTEM_INFO SI;
	memset(&SI, 0, sizeof(SI));
	GetSystemInfo(&SI);

	DWORD dwAddress = (DWORD)SI.lpMaximumApplicationAddress - size;     // maximum address space - size of requests
	dwAddress = dwAddress - (dwAddress % SI.dwAllocationGranularity);   // round down to allocation granularity
	dwAddress -= 512 * SI.dwAllocationGranularity;						// go down 512 pages. 
	return (LPVOID)dwAddress;
}


void ErrorExit(LPCTSTR pszMessage)
{
	_tprintf(_T("%s lasterror=%d\n"), pszMessage, GetLastError());
	exit(1);
}

static LPVOID g_pRegion = NULL;

// allocate shared memory. Return a pointer to IT, and set it into the environment variable.
LPVOID AllocateSharedMemory(DWORD size)
{
	if (g_pRegion != NULL)	// if we've already made the allocation in this process, return what we have.
		return g_pRegion;
	
	HANDLE hFileMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, NULL);
	if (hFileMapping == NULL)
	{
		ErrorExit(_T("ERROR CreateFileMapping"));
	}

	LPVOID pGuess = GuessSafeAddress(size);
	LPVOID pRegion = MapViewOfFileEx(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, pGuess);
	if (pRegion == NULL)
	{
		ErrorExit(_T("**ERROR allocating Region lasterror"));
	}

	HANDLE hCurrentProcess = OpenProcess(PROCESS_DUP_HANDLE, TRUE, GetCurrentProcessId());

	// copy address into first 4 bytes, so we know it's the one we are expecting.
	DWORD dwRegion = (DWORD)pRegion;
	memcpy(pRegion, &dwRegion, sizeof(DWORD));


	TCHAR szEnvVar[200];
	_stprintf_s(szEnvVar, _T("%8.8x-%8.8x-%8x8x"), (DWORD)hCurrentProcess, (DWORD)hFileMapping, (DWORD)pRegion);

	SetEnvironmentVariable(ENVIRONMENT_VAR, szEnvVar);

	g_pRegion = pRegion;		// store it globally.
	return pRegion;
}


LPVOID GetSharedMemory()
{
	if (g_pRegion != NULL)	// if we've already made the allocation in this process, return what we have.
		return g_pRegion;
	
	TCHAR szEnvVar[200];
	if (GetEnvironmentVariable(ENVIRONMENT_VAR, szEnvVar, sizeof(szEnvVar)) == 0)
	{
		ErrorExit(_T("Failed to read environment variable"));
	}
	HANDLE hParentProcess;
	HANDLE hFileMappingInParent;
	LPVOID pRegionAllocated;

	_stscanf_s(szEnvVar, _T("%8x-%8x-%8x"), (LPDWORD)&hParentProcess, (LPDWORD)&hFileMappingInParent, (LPDWORD)&pRegionAllocated);
	printf("Process=%8.8x Handle=%8.8x  pointer=%8.8x", (DWORD)hParentProcess, (DWORD)hFileMappingInParent, (DWORD)pRegionAllocated);

	HANDLE hFileMappingInMe = 0;
	if (DuplicateHandle(hParentProcess, hFileMappingInParent, GetCurrentProcess(), &hFileMappingInMe, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
	{
		ErrorExit(_T("ERROR DuplicateHandle"));
	}

	LPVOID pRegion = MapViewOfFileEx(hFileMappingInMe, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0, pRegionAllocated);
	if (pRegion == NULL)
	{
		ErrorExit(_T("MapViewOfFileEx"));
	}

	// check the values match
	if (memcmp(pRegion, &pRegionAllocated, 4) != 0)
	{
		ErrorExit(_T("Region allocation check failed"));
	}

	g_pRegion = pRegion;
	return pRegion;
}





void LaunchChildProcesses(int num_processes)
{
	for (int i = 0; i < num_processes; i++)
	{
		TCHAR szCmdLine[200];
		_stprintf_s(szCmdLine, _countof(szCmdLine), _T("aslrpoc.exe"));
		STARTUPINFO SI;
		memset(&SI, 0, sizeof(SI));
		SI.cb = sizeof(STARTUPINFO);
		PROCESS_INFORMATION PI;
		memset(&PI, 0, sizeof(PROCESS_INFORMATION));

		_tprintf(_T("MAIN launching %s\n"), szCmdLine);
		BOOL ret = CreateProcess(NULL,
			szCmdLine,
			NULL,
			NULL,
			FALSE, //TRUE,  //inherit handles - this has to be true, or else we can access the handles in the child process at all.
			NORMAL_PRIORITY_CLASS,
			NULL,
			NULL,
			&SI,
			&PI);
		printf("Created process %8.8x\n", PI.dwProcessId);
	}
}




int main(int argc, const char* argv[])
{
	DWORD size = 64 * 1024;
	int num_processes = 5;

	if (argc > 1 && _stricmp(argv[1], "main") == 0)
	{
		LPVOID pVoid = AllocateSharedMemory(size);

		LaunchChildProcesses(num_processes);
		Sleep(5000);  // delay to allow children to stop.
	}
	else
	{
		LPVOID pVoid = GetSharedMemory();
		printf(" PASS\n");
	}
}




