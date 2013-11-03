


#include <Windows.h>
#include <stdio.h>
#include <iostream>


#include <Psapi.h>


typedef struct HookData
{
	int Index;
	ULONG Addr;

}cHookData;

int NtIndex(char *Service)
{
	int index = 0;

	ReadProcessMemory(GetCurrentProcess(),LPVOID((DWORD)GetProcAddress(GetModuleHandle("ntdll"),Service)+1),&index,sizeof(int),NULL);

	return index;
}

DWORD OrginalAddress(int Index)
{
	LPVOID Drivers[1024];
	DWORD cbNeeded;
	EnumDeviceDrivers(Drivers,1024,&cbNeeded);

	char KernelName[255];
	GetDeviceDriverBaseName(Drivers[0],KernelName,255);

	HMODULE hKernel = LoadLibraryEx(KernelName,NULL,DONT_RESOLVE_DLL_REFERENCES);

	MODULEINFO modInf;
	ZeroMemory(&modInf,sizeof(MODULEINFO));
	GetModuleInformation(GetCurrentProcess(),hKernel,&modInf,sizeof(MODULEINFO));

	DWORD ActualKernelBase = (DWORD)hKernel;
	DWORD ActualKernelEnd = ActualKernelBase + modInf.SizeOfImage;

	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)( (DWORD)hKernel + ((PIMAGE_DOS_HEADER)hKernel)->e_lfanew);

	DWORD OrgKernelBase = INH->OptionalHeader.ImageBase;
	DWORD OrgKernelEnd = OrgKernelBase + INH->OptionalHeader.SizeOfImage;

	PVOID ActualProcAddr = GetProcAddress(hKernel,"NtCreateFile");
	DWORD NtAddr = (DWORD)ActualProcAddr - ActualKernelBase + OrgKernelBase;

	 DWORD dwCurDword = 0;
        DWORD dwPrevDword = 0;
        DWORD dwNextDword = 0;
		DWORD SsdtAddress ;
        for( PBYTE i = (PBYTE)ActualKernelBase + sizeof(DWORD); i < (PBYTE)ActualKernelEnd - sizeof(DWORD); i++ )
        {
            dwCurDword = *(PDWORD)i;
            dwPrevDword = *(PDWORD)( i - sizeof(DWORD) );
            dwNextDword = *(PDWORD)( i + sizeof(DWORD) );

            if( ( dwCurDword == NtAddr ) &&
                ( ( dwPrevDword >= OrgKernelBase ) && ( dwPrevDword <= OrgKernelEnd ) ) &&
                ( ( dwNextDword >= OrgKernelBase ) && ( dwNextDword <= OrgKernelEnd ) ) )
            {
                SsdtAddress = (DWORD)i;
                break;
            }
        }

        // Get system's NT kernel image base
        DWORD dwSystemNtKernelBase = (DWORD)Drivers[0];
   
            // Now, calculate NtXxx address of specified unction in system's NT kernel image
            DWORD dwSsdtAddress = SsdtAddress + ( Index - NtIndex("NtCreateFile") )*sizeof(DWORD);
            DWORD dwNtAddress = *(PDWORD)dwSsdtAddress - OrgKernelBase + dwSystemNtKernelBase;
        

	return dwNtAddress;
}


int main()
{

	SetConsoleTitleA("unHooker -  BETA Edition | By : unCoder  ");

	printf("\n\                          SSDT Kernel unHooker \n");

	printf("\n\                            By : unCoder \n");

	printf("\n                        WebSite : www.dev-point.com  \n");
	
	printf("\n                Thanks to : Simon-Benyo | ColdZer0 | NativeCall \n\n");
	
	Sleep(500);

    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS ss;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    
    printf("\n [+] Loading Driver");
	Sleep(500);

    if(hSCManager)
    {
        printf("\n [+] Creating Service");
		Sleep(500);

        hService = CreateService(hSCManager, "uHo",
                                 "uHo Driver",
                                  SERVICE_START | DELETE | SERVICE_STOP,
                                  SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START,
                                  SERVICE_ERROR_IGNORE,
                                  "\\unHooker.sys", 
                                  NULL, NULL, NULL, NULL, NULL);

        if(!hService)
        {
            hService = OpenService(hSCManager, "uHo", 
                       SERVICE_START | DELETE | SERVICE_STOP);
        }

        if(hService)
        {
            printf("\n [+] Starting Service");
			Sleep(500);

            StartService(hService, 0, NULL);

			HANDLE hFile;
			 hFile = CreateFileA("\\\\.\\uHo", 
            GENERIC_READ | GENERIC_WRITE, 0, 0,
			OPEN_EXISTING,FILE_ATTRIBUTE_SYSTEM, NULL);

			 if(hFile == (HANDLE)-1) { printf("\n [-] Error to open the service");goto ex; }

			 printf("\n [+] Service Handle is : %d",hFile); 
			 Sleep(500);

			DWORD wrtn;
			char *procName;

			cHookData data;
			std::cout << "\n [?] Enter NativeService Name : ";
			std::cin >> procName;
		
			data.Index = NtIndex(procName);
			
			if(!data.Index > 0)
			{
				printf("\n [-] Error getting NtService Index [ Check the APi(Service) Name ]");
				return 0;
			}

			printf("\n [+] Calculating OrginalAddress.. | NtService Index : %d",data.Index);
			Sleep(500);

			data.Addr = OrginalAddress(data.Index);

			if(!data.Addr > 0)
			{
				printf("\n [-] Error getting NtService OrginalAddress");
				return 0;
			}

			printf("\n [+] NtService OrginalAddress : 0x%X",data.Addr);
			Sleep(500);

			if(DeviceIoControl(hFile,(DWORD)200001,&data,sizeof(data),NULL,NULL,&wrtn,NULL))
				printf("\n [+] %s unHooked Successfully\n [+] SSDT Pointer Returend to : 0x%X",procName,data.Addr);

	
			CloseHandle(hFile);

            printf("\n Press Enter to UnloadDriver (CloseService)");
            getchar();

            ControlService(hService, SERVICE_CONTROL_STOP, &ss);

            DeleteService(hService);

			printf("\n [+] DeviceDriver Unloaded ");
			Sleep(300);

            CloseServiceHandle(hService);
            
        }

        CloseServiceHandle(hSCManager);
    }
	else { printf("\n [-] Error while Loading the driver"); }
    
	ex:
	printf("\n\n Press Enter to Exit ..");
	getchar();
    return 0;

}