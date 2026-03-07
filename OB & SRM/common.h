#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdio>

// =================================================================

#define WXSTATUS_FAILED 0xCFFFFFFF
#define WXSTATUS_SUCCESS 0x0
#define WXSTATUS_NOT_FOUND 0xC0000001
#define WXSTATUS_VETO_OPERATION 0xC0000002
#define WX_INVALID_ACCESS_RIGHT 0x0

#define WX_SUCCESS(wx_status) (((INT)wx_status) >= 0x0) 


// =================================================================

typedef DWORD KPROCESSOR_MODE;
typedef NTSTATUS WXSTATUS;
typedef HANDLE WXHANDLE;
typedef DWORD WX_ACCESS_MASK;
typedef LONG WX_SECRURITY_AUTHORITY;
typedef DWORD WX_IMPERSONATION_LEVEL;

typedef struct _OBJECT_HEADER OBJECT_HEADER, * POBJECT_HEADER, * LPOBJECT_HEADER;

// =================================================================

typedef struct _WX_LIST_ENTRY {
	struct _WX_LIST_ENTRY* Flink;
	struct _WX_LIST_ENTRY* Blink;
} WX_LIST_ENTRY, * PWX_LIST_ENTRY, * LPWX_LIST_ENTRY;

// =================================================================

// Doubly Linked list functions
void __stdcall WxInitializeListHead(PWX_LIST_ENTRY);
void __stdcall WxInsertTailList(PWX_LIST_ENTRY, PWX_LIST_ENTRY);
void __stdcall WxRemoveFromList(PWX_LIST_ENTRY);

// helpers
BOOLEAN __stdcall IsBadPointer(LPVOID);
BOOLEAN __stdcall cmp(LPBYTE, LPBYTE, SIZE_T);

// =================================================================