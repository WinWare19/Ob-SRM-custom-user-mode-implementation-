#pragma once
#include "./common.h"
#include "./srm.h"

// ==========================================================

#define USER_MODE 0x1
#define KERNEL_MODE 0x2

#define OB_NAME_ENTRY_FLAG_DIRECTORY 0x1000
#define OB_NAME_ENTRY_FLAG_SYMBOLIC_LINK 0x10000
#define OB_NAME_ENTRY_FLAG_PRIVATE_ENTRY 0x20000

#define OB_OBJECT_TYPE_OBJECT_DIRECTORY 0x8000
#define OB_OBJECT_TYPE_DEVICE 0X9000
#define OB_OBJECT_TYPE_ACCESS_TOKEN 0x10000
#define OB_OBJECT_TYPE_MASK (OB_OBJECT_TYPE_ACCESS_TOKEN | OB_OBJECT_TYPE_OBJECT_DIRECTORY | OB_OBJECT_TYPE_DEVICE)

#define OB_OPENED 0x6000
#define OB_CREATED 0x7000

#define OB_HANDLE_ATTRIBUTE_INHERIT 0x40000
#define OB_HANDLE_ATTRIBUTE_KERNEL 0x400000

#define OB_PRE_CALLBACK 0x50000
#define OB_POST_CALLBACK 0x60000

#define OB_PRE_CREATE_CALLBACK 0x0
#define OB_POST_CREATE_CALLBACK 0x1
#define OB_PRE_DUPLICATE_CALLBACK 0x2
#define OB_POST_DUPLICATE_CALLBACK 0x3
#define OB_PRE_DELETE_CALLBACK 0x4
#define OB_POST_DELETE_CALLBACK 0x5

#define OB_OBJECT_HEADER_SIGNATURE 0xEBDC

// ==========================================================

typedef struct _OBJECT_NAME_ENTRY OBJECT_NAME_ENTRY, * POBJECT_NAME_ENTRY, * LPOBJECT_NAME_ENTRY;
typedef struct _OBJECT_TYPE OBJECT_TYPE, * POBJECT_TYPE, * LPOBJECT_TYPE;

typedef WXSTATUS(__stdcall* ObEventHandler)(LPOBJECT_HEADER);
typedef WXSTATUS(__stdcall* ObNameLookupRoutine)(LPOBJECT_HEADER, LPCWSTR, ULONG);
typedef WXSTATUS(__stdcall* ObCallback)(LPOBJECT_HEADER, ULONG_PTR);
typedef WXSTATUS(__stdcall* ObAccessRightsMappingRoutine)(LPOBJECT_TYPE, WX_ACCESS_MASK, WX_ACCESS_MASK*);

struct _OBJECT_NAME_ENTRY {
	DWORD flags;
	CRITICAL_SECTION lock;
	UNICODE_STRING name;
	WX_LIST_ENTRY link, direct_children_list_head;
	_OBJECT_NAME_ENTRY* direct_parent;
	union {
		_OBJECT_HEADER* object_hdr;
		_OBJECT_NAME_ENTRY* link_target;
	};
};
struct _OBJECT_TYPE {
	ULONG type_id;
	CRITICAL_SECTION lock;
	WX_LIST_ENTRY link, objects_list_head;
	ObEventHandler OnQueryCreate, OnCreate, OnQueryDelete, OnDelete, OnQueryClose, OnClose, OnQueryOpen, OnOpen;
	ObNameLookupRoutine LookupPrivateNamespace;
	ObAccessRightsMappingRoutine ObGenericAccessRightsMapper;
	WX_ACCESS_MASK valid_acess_rights_mask;
};
struct _OBJECT_HEADER {
	WORD signature;
	SIZE_T body_size;
	ULONG ref_count, handle_count;
	CRITICAL_SECTION lock;
	WX_LIST_ENTRY link;
	OBJECT_NAME_ENTRY* name_entry;
	OBJECT_TYPE* object_type;
	PWX_SECURITY_DESCRIPTOR security_descriptor;
};
typedef struct _HANDLE_TABLE {
	ULONG ____next_val;
	CRITICAL_SECTION lock;
	WX_LIST_ENTRY handles_list_head;
} HANDLE_TABLE;
typedef struct _HANDLE_ENTRY {
	ULONG value, attributes;
	ACCESS_MASK granted_access_rights;
	WX_LIST_ENTRY link;
	LPOBJECT_HEADER object_hdr;
	CRITICAL_SECTION lock;
} HANDLE_ENTRY, * PHANDLE_ENTRY, * LPHANDLE_ENTRY;
typedef struct _OBJECT_CALLBACK {
	ULONG type;
	LPOBJECT_TYPE object_type;
	ObCallback callback_routine;
	ULONG_PTR callback_routine_context;
	WX_LIST_ENTRY link;
} OBJECT_CALLBACK, * POBJECT_CALLBACK, * LPOBJECT_CALLBACK;
typedef struct _WX_OBJECT_MANAGER {
	WX_LIST_ENTRY namespace_root, object_type_list_head, ob_callbacks[0x6];
	CRITICAL_SECTION namespace_lock, object_types_lock, callback_locks[0x6];
	HANDLE_TABLE* kernel_handle_table, *user_handle_table;
} WX_OBJECT_MANAGER, * PWX_OBJECT_MANAGER, * LPWX_OBJECT_MANAGER;

// ==========================================================

// event handlers
WXSTATUS __stdcall ObpOnQueryCreate(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnCreate(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnQueryOpen(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnOpen(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnQueryClose(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnClose(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnQueryDelete(OBJECT_HEADER*);
WXSTATUS __stdcall ObpOnDelete(OBJECT_HEADER*);
WXSTATUS __stdcall ObpLookupPrivateNamespace(OBJECT_HEADER*, LPCWSTR, ULONG);
WXSTATUS __stdcall ObMapGenericAccessRights(OBJECT_TYPE*, WX_ACCESS_MASK, WX_ACCESS_MASK*);

// object manager functions
WXSTATUS __stdcall ObInitializeWxObjectManager();
WXSTATUS __stdcall ObpInitialize();
WXSTATUS __stdcall ObInitializeHandleTable(HANDLE_TABLE*);
WXSTATUS __stdcall ObCreateObjectType(ULONG, WX_ACCESS_MASK, OBJECT_TYPE**);
WXSTATUS __stdcall ObCreateObject(ULONG, LPCWSTR, ULONG, SIZE_T, LPWX_SECURITY_DESCRIPTOR, LPOBJECT_HEADER*, ULONG*);
WXSTATUS __stdcall ObCreateHandle(HANDLE_TABLE*, LPVOID, ULONG, WX_ACCESS_MASK, WXHANDLE*);
WXSTATUS __stdcall ObAllocateNameEntry(LPCWSTR, ULONG, DWORD, LPOBJECT_NAME_ENTRY*, LPOBJECT_NAME_ENTRY);
WXSTATUS __stdcall ObLookupHandleTable(HANDLE_TABLE*, WXHANDLE, LPHANDLE_ENTRY*);
WXSTATUS __stdcall ObCloseHandle(WXHANDLE, KPROCESSOR_MODE);
void __stdcall ObCallPreCallbacks(LPOBJECT_HEADER, ULONG, LPOBJECT_TYPE);
void __stdcall ObCallPostCallbacks(LPOBJECT_HEADER, ULONG, LPOBJECT_TYPE);
WXSTATUS __stdcall ObOpenObjectByName(LPCWSTR, ULONG, KPROCESSOR_MODE, ULONG, WX_ACCESS_MASK, WXHANDLE*);
WXSTATUS __stdcall ObOpenObjectByPointer(LPVOID, KPROCESSOR_MODE, ULONG, WX_ACCESS_MASK, WXHANDLE*);
WXSTATUS __stdcall ObReferenceObjectByHandle(WXHANDLE, KPROCESSOR_MODE, LPOBJECT_TYPE, ACCESS_MASK, LPVOID*);
WXSTATUS __stdcall ObReferenceObject(LPVOID, ULONG*);
WXSTATUS __stdcall ObDereferenceObject(LPVOID, ULONG*);
WXSTATUS __stdcall ObMakeObjectParmanent(LPVOID);
WXSTATUS __stdcall ObMakeObjectTemporary(LPVOID);
BOOLEAN __stdcall ObIsKernelHandle(WXHANDLE);
WXSTATUS __stdcall ObDuplicateHandle(WXHANDLE, HANDLE_TABLE*, WX_ACCESS_MASK, WXHANDLE*);
WXSTATUS __stdcall ObRegisterCallback(ULONG, ULONG, ObCallback, ULONG_PTR, WX_LIST_ENTRY**);
WXSTATUS __stdcall ObUnregisterCallback(WX_LIST_ENTRY*);
WXSTATUS __stdcall ObGetObjectName(WXHANDLE, LPWSTR*, ULONG*);

// helpers
LPOBJECT_HEADER __stdcall ObGetObjectHeader(LPVOID);
BOOLEAN __stdcall ObIsValidName(LPCWSTR, ULONG);
WXSTATUS __stdcall ObLookupGlobalNamespace(LPCWSTR, ULONG, LPOBJECT_NAME_ENTRY**, ULONG*, ULONG*);

// ==========================================================

LPWX_OBJECT_MANAGER __object_manager = 0x0;
KPROCESSOR_MODE requestor_mode = USER_MODE;


// ==========================================================
