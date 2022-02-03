#include <ntifs.h>

#include "device_handlers.h"
#include "consts.h"
#include "common.h"
#include "dll_injection.h"

PETHREAD thread_object = nullptr;
BOOLEAN end_listen_thread = FALSE;
BOOLEAN has_injected = FALSE;

#define FLAG_TEXT "owl246"
#define FLAG_LENGTH_PLUS_ONE 7 // me when needs to be constant? huh?
#define FLAG_FILE_PATH L"\\DosDevices\\C:\\Users\\Natha\\Documents\\Rockstar_Password.txt"
#define DLL_PATH L"C:\\Users\\Natha\\Programming\\OwlHook\\x64\\Release\\OwlHook.dll"
#define TARGET_PROC_NAME "javaw.exe"

/* function as driver callback upon being unloaded */
void driver_unload(PDRIVER_OBJECT driver_object) 
{
	end_listen_thread = TRUE; // notify and wait for our listening thread to finish up
	KeWaitForSingleObject( thread_object, 
		Executive,
		KernelMode,
		FALSE,
		NULL);

	ObDereferenceObject(thread_object);

	UNICODE_STRING  win32_name;
	RtlInitUnicodeString(&win32_name, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&win32_name);

	if (nullptr != driver_object->DeviceObject) 
	{
		IoDeleteDevice(driver_object->DeviceObject);
	}
}

/* find a proccess from binary name, return STATUS_SUCCESS if found, set a pointer to proccess object */
NTSTATUS find_proccess(CHAR* process_name, PEPROCESS* process)
{
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS cur_entry = sys_process;

	CHAR image_name[15];

	do
	{
		RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8), sizeof(image_name));

		if (strstr(image_name, process_name))
		{
			DWORD64 active_threads;
			RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0), sizeof(active_threads));
			if (active_threads)
			{
				*process = cur_entry;
				return STATUS_SUCCESS;
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+0x448) /*EPROCESS->ActiveProcessLinks*/;
		cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

	} while (cur_entry != sys_process);

	return STATUS_NOT_FOUND;
}

/* when ready, injects our dll into the target proccess */
void load_dll(ULONG pid)
{
	InjectDllArgs args = {};
	memcpy(args.dll_path, DLL_PATH, 
		wcslen(DLL_PATH) * sizeof(wchar_t));
	PEPROCESS t;
	args.pid = pid;

	NTSTATUS nt_status = inject_dll(args);
}

/* scans our control file for the flag, and returns true so we know we are good to inject */
BOOLEAN flagged_to_inject()
{
	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;

	RtlInitUnicodeString(&uniName, FLAG_FILE_PATH);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE   handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	LARGE_INTEGER      byteOffset;

	#define  BUFFER_SIZE FLAG_LENGTH_PLUS_ONE
	CHAR     buffer[FLAG_LENGTH_PLUS_ONE];

	ntstatus = ZwCreateFile(&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(ntstatus)) 
	{
		byteOffset.LowPart = byteOffset.HighPart = 0;
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			buffer, BUFFER_SIZE, &byteOffset, NULL);

		if (NT_SUCCESS(ntstatus)) 
		{
			buffer[BUFFER_SIZE - 1] = '\0';
		}
	}

	ZwClose(handle);

	int i = strcmp(buffer, FLAG_TEXT);

	if (i == 0)
	{
		return TRUE;
	}

	#undef BUFFER_SIZE

	return FALSE;
}

/* main thread for listening on our flag file, runs a simple clock and basic logic */
VOID listen_thread(IN PVOID context)
{
	ULONG current_time = 5;
	ULONG clock = 4;

	while (end_listen_thread == FALSE)
	{
		clock++;

		if (end_listen_thread) break;

		if (clock - current_time > 1000000000) // once every bit or so idk
		{
			current_time = clock;

			if (flagged_to_inject() == TRUE && has_injected == FALSE)
			{
				PEPROCESS myproc;
				NTSTATUS s = find_proccess(TARGET_PROC_NAME, &myproc);
				ULONG pid;

				if (NT_SUCCESS(s))
				{
					load_dll((ULONG)PsGetProcessId(myproc));

					has_injected = true;
				}
			}
			else 
			{
				has_injected = FALSE;
			}
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

/* entry function, initialize all the device stuff (not needed for my impl), sets thread handles and runs it */
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) 
{
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING  nt_name;
	UNICODE_STRING  win32_name;
	PDEVICE_OBJECT  device_object = nullptr;

	RtlInitUnicodeString(&nt_name, NT_DEVICE_NAME);
	NTSTATUS nt_status = IoCreateDevice(driver_object, 0, &nt_name,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
		TRUE, &device_object);

	if (!NT_SUCCESS(nt_status)) 
	{
		return nt_status;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] = device_create_close;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = device_create_close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = device_ioctl;
	driver_object->DriverUnload = driver_unload;

	RtlInitUnicodeString(&win32_name, DOS_DEVICE_NAME);

	nt_status = IoCreateSymbolicLink(&win32_name, &nt_name);
	if (!NT_SUCCESS(nt_status)) 
	{
		IoDeleteDevice(device_object);
	}

	HANDLE ThreadHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;

	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status = PsCreateSystemThread(&ThreadHandle,
		THREAD_ALL_ACCESS,
		&ObjectAttributes,
		NULL,
		NULL,
		(PKSTART_ROUTINE)listen_thread,
		NULL);

	ObReferenceObjectByHandle(ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID*)&thread_object,
		NULL);

	ZwClose(ThreadHandle);

	return nt_status;
}