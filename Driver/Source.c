
//	# unHooker Driver [ UNCODER ]
	

#include <Ntddk.h>
typedef struct HookData
{
	int Index;
	ULONG Addr;
}cHookData;

// Service Description Table (SDT)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; 
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *PointerServiceDescriptorTableEntry;

// Import KeServiceDescriptorTable from ntoskrnl.exe
__declspec(dllimport)  ServiceDescriptorTableEntry KeServiceDescriptorTable;


UNICODE_STRING DosName,Name;
void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&DosName);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("Unloaded - unCoder ");
}

NTSTATUS __stdcall UnhookSsdtService(IN cHookData data)
{
	// Disable the Memory Write Protection so we can access the protected System Service Dispatch Table (SSDT)
	_asm
	{
	CLI										
	MOV	EAX, CR0		
	AND EAX, NOT 10000H 
	MOV	CR0, EAX		
	}

	KeServiceDescriptorTable.ServiceTableBase[data.Index] = (ULONG)data.Addr;
	
	_asm 
	{
	MOV	EAX, CR0		
	OR	EAX, 10000H		
	MOV	CR0, EAX		
	STI					
	}
	
	DbgPrint("unHooked - unCoder");   
	
	return STATUS_SUCCESS;
}

NTSTATUS __stdcall  IoCreate(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	IofCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}
NTSTATUS __stdcall IRP_DEVICE_CONTROL(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	cHookData data;
	memcpy(&data,Irp->AssociatedIrp.SystemBuffer,sizeof(data));

	UnhookSsdtService(data);
	IofCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegPath)
{
	NTSTATUS NtStatus;
	PDEVICE_OBJECT DeviceObject;

	RtlInitUnicodeString(&DosName,L"\\DosDevices\\uHo");
	RtlInitUnicodeString(&Name,L"\\Device\\uHo");
	
	NtStatus = IoCreateDevice(DriverObject,0,&Name,FILE_DEVICE_UNKNOWN,0,FALSE,&DeviceObject);
	IoCreateSymbolicLink(&DosName,&Name);
	
	DbgPrint("Driver Loaded - unCoder");
	
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreate;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_DEVICE_CONTROL;
	DriverObject->DriverUnload = DriverUnload;
	
	
	return NtStatus;
}