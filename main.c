#include <windows.h>
#include <stdio.h>


#include "ntdll.h"

int main(int argc, char *argv[])
{
	HANDLE hThread;

	NTSTATUS status;

	char *buffer = argv[2];
	int procID = atoi(argv[1]);
	printf("\n[*] InjectorX : Inject WIthout Limits");
	printf("\n[*] Author : @Ice3man");
	printf("\n[*] Supplied Args | PID = %i : Dll Path = %s", procID, buffer);

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

	if(process==NULL)
	{
		printf("\n\n[*] Specified Process Doesn't Exist");
	}
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if(addr==NULL)
	{
		printf("\n[*] Library Addresses not Found");
	}
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(arg==NULL)
	{
		printf("\n[*] Could Not Allocate Memory for Dll");
	}
	int n = WriteProcessMemory(process, arg, buffer, strlen(buffer), NULL);
	if(n==0)
	{
		printf("\n[*] No bytes were written to the target Process");
	}
	status=RtlCreateUserThread(process,NULL,FALSE,0,0,0,(PUSER_THREAD_START_ROUTINE)addr, arg,&hThread,NULL); // Start Thread
	if(!NT_SUCCESS(status))
	{
		printf("\n[*] Error Occured Creating A Thread");
		return -1;
	}
	printf("\nThread created\n");
	return 0;
}
