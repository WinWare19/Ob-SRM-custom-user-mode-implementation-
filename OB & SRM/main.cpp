#include "./ob.h"

INT main() {

	WXSTATUS wx_status = ObInitializeWxObjectManager();
	if (!WX_SUCCESS(wx_status)) return 0x0;

	printf_s("Object Manager initialized successfully ... .. .\n");

	wx_status = SeInitializeWxSecurityReferenceMonitor();
	if (!WX_SUCCESS(wx_status)) return 0x0;

	printf_s("Security Reference Monitor initialized successfully ... .. .\n");

	LPWX_ACCESS_TOKEN access_token = 0x0;
	wx_status = SeLogonUser(default_user_name, lstrlenW(default_user_name), 0x0, 0x0, &access_token);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(access_token)) return 0x0;

	printf_s("%ws\\%ws logged in successfully ... .. .\n\n", computer_name, default_user_name);

	WX_ACCESS_MASK granted_access_rights = 0x0;
	wx_status = SeAccessCheck(access_token, access_token, WX_INVALID_ACCESS_RIGHT, &granted_access_rights);

	printf_s("access check status:\n%ws { granted access rights: 0x%X }\n", WX_SUCCESS(wx_status) ? L"Allowed" : L"Denied", granted_access_rights);

	ObDereferenceObject(access_token, 0x0);

	return 0x0;
}

// ========================================================================

BOOLEAN __stdcall IsBadPointer(LPVOID pointer) {
	if (!pointer) return 0x1;
	__try {
		*(LPBYTE*)pointer = *(LPBYTE*)pointer;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0x1;
	}
	return 0x0;
}

void __stdcall WxInitializeListHead(PWX_LIST_ENTRY list_head) {
	if (!list_head) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	list_head->Flink = list_head->Blink = list_head;
}

void __stdcall WxInsertTailList(PWX_LIST_ENTRY list_head, PWX_LIST_ENTRY new_entry) {
	if (!list_head || !new_entry || !list_head->Blink || !list_head->Flink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	new_entry->Flink = list_head;
	new_entry->Blink = list_head->Blink;
	list_head->Blink->Flink = new_entry;
	list_head->Blink = new_entry;
}

void __stdcall WxRemoveFromList(PWX_LIST_ENTRY entry_to_remove) {
	if (!entry_to_remove || !entry_to_remove->Flink || !entry_to_remove->Blink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	entry_to_remove->Blink->Flink = entry_to_remove->Flink;
	entry_to_remove->Flink->Blink = entry_to_remove->Blink;

	entry_to_remove->Flink = entry_to_remove->Blink = 0x0;
}

BOOLEAN __stdcall cmp(LPBYTE op_0, LPBYTE op_1, SIZE_T bytes_count) {
	if (!op_0 || !op_1 || !bytes_count) return 0x0;
	for (UINT i = 0x0; i < bytes_count; i++) if (op_0[i] != op_1[i]) return 0x0;
	return 0x1;
}

// ======================== OBJECT MANAGER ================================

WXSTATUS __stdcall ObInitializeWxObjectManager() {
	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	__object_manager = (WX_OBJECT_MANAGER*)HeapAlloc(default_heap, 0x8, sizeof WX_OBJECT_MANAGER);
	if (IsBadPointer(__object_manager)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_FAILED;

	__object_manager->kernel_handle_table = (HANDLE_TABLE*)HeapAlloc(default_heap, 0x8, sizeof HANDLE_TABLE);
	if (IsBadPointer(__object_manager->kernel_handle_table)) goto FREE_OBJECT_MANAGER;
	else {
		__object_manager->user_handle_table = (HANDLE_TABLE*)HeapAlloc(default_heap, 0x8, sizeof HANDLE_TABLE);
		if (!__object_manager->user_handle_table) goto FREE_KERNEL_HANDLE_TABLE;
		else {
			wx_status = ObInitializeHandleTable(__object_manager->kernel_handle_table);
			if (!WX_SUCCESS(wx_status)) goto FREE_USER_HANDLE_TABLE;
			else {
				wx_status = ObInitializeHandleTable(__object_manager->user_handle_table);
				if (!WX_SUCCESS(wx_status)) goto FREE_USER_HANDLE_TABLE;
				else goto INITIALIZE_OB_NAMESPACE;
			}
		}
	FREE_USER_HANDLE_TABLE:
		if (!IsBadPointer(__object_manager->user_handle_table)) HeapFree(default_heap, 0x0, __object_manager->user_handle_table);
	}
FREE_KERNEL_HANDLE_TABLE:
	if (!IsBadPointer(__object_manager->kernel_handle_table)) HeapFree(default_heap, 0x0, __object_manager->kernel_handle_table);
FREE_OBJECT_MANAGER:
	if (!IsBadPointer(__object_manager)) HeapFree(default_heap, 0x0, __object_manager);
	goto EPILOGUE;
INITIALIZE_OB_NAMESPACE:
	for (UINT i = 0x0; i < 0x6; i++) {
		InitializeCriticalSection(&__object_manager->callback_locks[i]);
		WxInitializeListHead(&__object_manager->ob_callbacks[i]);
	}
	wx_status = ObpInitialize();
	if (!WX_SUCCESS(wx_status)) {
		for (UINT i = 0x0; i < 0x6; i++) DeleteCriticalSection(&__object_manager->callback_locks[i]);
		goto FREE_USER_HANDLE_TABLE;
	}
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObpInitialize() {
	if (IsBadPointer(__object_manager)) return WXSTATUS_FAILED;

	InitializeCriticalSection(&__object_manager->object_types_lock);
	WxInitializeListHead(&__object_manager->object_type_list_head);

	InitializeCriticalSection(&__object_manager->namespace_lock);
	WxInitializeListHead(&__object_manager->namespace_root);

	WXSTATUS wx_status = WXSTATUS_FAILED;

	LPOBJECT_TYPE object_type = 0x0;
	if (!WX_SUCCESS(ObCreateObjectType(OB_OBJECT_TYPE_OBJECT_DIRECTORY, 0x0, &object_type))) goto DELETE_OBJECT_TYPES_LOCK;
	else {
		LPOBJECT_HEADER object_hdr[0x3] = { 0x0 };
		LPCWSTR dir_names[] = { L"\\Device", L"\\Registry", L"\\Driver", L"\\DosDevices", L"\\??" };

		for (UINT i = 0x0; i < 0x3; i++) {
			wx_status = ObCreateObject(OB_OBJECT_TYPE_OBJECT_DIRECTORY, dir_names[i], lstrlenW(dir_names[i]),
				0x1, 0x0, &object_hdr[i], 0x0);
			if (!WX_SUCCESS(wx_status)) break;
		}

		if (!WX_SUCCESS(wx_status)) goto DELETE_OBJECT_DIRECTORIES;
		else {
			LPOBJECT_NAME_ENTRY name_entry[0x2] = { 0x0 };
			for (UINT i = 0x0; i < 0x2; i++)
				if (WX_SUCCESS(ObAllocateNameEntry(dir_names[i] + 0x1, (ULONG)lstrlenW(dir_names[i + 3] + 0x1), OB_NAME_ENTRY_FLAG_DIRECTORY |
					OB_NAME_ENTRY_FLAG_SYMBOLIC_LINK, &name_entry[i], 0x0)) && !IsBadPointer(name_entry[i]))  name_entry[i]->link_target = i == 0x0 ? object_hdr[0x0]->name_entry :
					name_entry[0x0];
			wx_status = WXSTATUS_SUCCESS;
			goto EPILOGUE;
		}
	DELETE_OBJECT_DIRECTORIES:	
		for (UINT i = 0x0; i < 0x3; i++) if (!IsBadPointer(object_hdr[i])) ObDereferenceObject((LPVOID)((UINT_PTR)object_hdr[i] + sizeof _OBJECT_HEADER), 0x0);
	}
DELETE_OBJECT_TYPES_LOCK:
	DeleteCriticalSection(&__object_manager->object_types_lock);
DELETE_NAMESPACE_LOCK:
	DeleteCriticalSection(&__object_manager->namespace_lock);
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObInitializeHandleTable(HANDLE_TABLE* handle_table) {
	if (IsBadPointer(handle_table)) return WXSTATUS_FAILED;

	InitializeCriticalSection(&handle_table->lock);
	WxInitializeListHead(&handle_table->handles_list_head);
	handle_table->____next_val = 0x0;

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObAllocateNameEntry(LPCWSTR name, ULONG cch_name, DWORD flags, LPOBJECT_NAME_ENTRY* name_entry, LPOBJECT_NAME_ENTRY parent_node) {
	if (IsBadPointer(name_entry)) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	*name_entry = (OBJECT_NAME_ENTRY*)HeapAlloc(default_heap, 0x8, sizeof OBJECT_NAME_ENTRY);
	if (IsBadPointer(*name_entry)) return WXSTATUS_FAILED;

	(*name_entry)->name.Buffer = (LPWSTR)HeapAlloc(default_heap, 0x8, (cch_name + 0x1) * sizeof WCHAR);
	if (IsBadPointer((*name_entry)->name.Buffer)) {
		HeapFree(default_heap, 0x8, *name_entry);
		return WXSTATUS_FAILED;
	}

	(*name_entry)->name.Length = (USHORT)(cch_name * sizeof WCHAR);
	(*name_entry)->name.MaximumLength = (USHORT)((cch_name + 0x1) * sizeof WCHAR);
	(*name_entry)->flags = flags;
	(*name_entry)->direct_parent = 0x0;

	CopyMemory((*name_entry)->name.Buffer, name, (*name_entry)->name.Length);

	InitializeCriticalSection(&(*name_entry)->lock);
	WxInitializeListHead(&(*name_entry)->direct_children_list_head);

	WXSTATUS wx_status = WXSTATUS_SUCCESS;

	EnterCriticalSection(&__object_manager->namespace_lock);
	if (!parent_node) WxInsertTailList(&__object_manager->namespace_root, &(*name_entry)->link);
	else if (!IsBadPointer(parent_node)) {
		EnterCriticalSection(&parent_node->lock);
		WxInsertTailList(&parent_node->direct_children_list_head, &(*name_entry)->link);
		LeaveCriticalSection(&parent_node->lock);
		(*name_entry)->direct_parent = parent_node;
	}
	else {
		DeleteCriticalSection(&(*name_entry)->lock);
		wx_status = WXSTATUS_FAILED;
		HeapFree(default_heap, 0x8, (*name_entry)->name.Buffer);
		HeapFree(default_heap, 0x8, *name_entry);
	}
	LeaveCriticalSection(&__object_manager->namespace_lock);

	return wx_status;
}

BOOLEAN __stdcall ObIsValidName(LPCWSTR name, ULONG cch_name) {
	if (!name || !cch_name) return 0x0;
	for (ULONG i = 0x0; i < cch_name; i++) if (name[i] == L'\\' || name[i] == L'/') return 0x0;
	return 0x1;
}

WXSTATUS __stdcall ObCreateObjectType(ULONG type_id, WX_ACCESS_MASK valid_access_rights_mask, OBJECT_TYPE** object_type) {
	if (IsBadPointer(object_type)) return WXSTATUS_FAILED;

	*object_type = (OBJECT_TYPE*)HeapAlloc(GetProcessHeap(), 0x8, sizeof OBJECT_TYPE);
	if (IsBadPointer(*object_type)) return WXSTATUS_FAILED;

	(*object_type)->type_id = type_id;
	
	InitializeCriticalSection(&(*object_type)->lock);
	WxInitializeListHead(&(*object_type)->objects_list_head);

	(*object_type)->OnQueryCreate = ObpOnQueryCreate;
	(*object_type)->OnCreate = ObpOnCreate;
	(*object_type)->OnQueryOpen = ObpOnQueryOpen;
	(*object_type)->OnOpen = ObpOnOpen;
	(*object_type)->OnQueryDelete = ObpOnQueryDelete;
	(*object_type)->OnDelete = ObpOnDelete;
	(*object_type)->OnQueryClose = ObpOnQueryClose;
	(*object_type)->OnClose = ObpOnClose;
	(*object_type)->LookupPrivateNamespace = ObpLookupPrivateNamespace;
	(*object_type)->ObGenericAccessRightsMapper = ObMapGenericAccessRights;

	(*object_type)->valid_acess_rights_mask = valid_access_rights_mask;

	EnterCriticalSection(&__object_manager->object_types_lock);

	WxInsertTailList(&__object_manager->object_type_list_head, &(*object_type)->link);

	LeaveCriticalSection(&__object_manager->object_types_lock);

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObCreateHandle(HANDLE_TABLE* handle_table, LPVOID object_body, ULONG attributes, WX_ACCESS_MASK access_rights, WXHANDLE* out_handle) {
	if (IsBadPointer(handle_table) || IsBadPointer(object_body) || IsBadPointer(out_handle) || 
		((attributes & OB_HANDLE_ATTRIBUTE_KERNEL) && handle_table != __object_manager->kernel_handle_table)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	LPOBJECT_HEADER object_hdr = ObGetObjectHeader(object_body);
	if (IsBadPointer(object_hdr) || object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) return WXSTATUS_FAILED;

	EnterCriticalSection(&object_hdr->object_type->lock);

	wx_status = object_hdr->object_type->OnQueryOpen(object_hdr);
	if (!WX_SUCCESS(wx_status)) goto UNLOCK_OBJECT_TYPE;
	else {
		ObCallPreCallbacks(object_hdr, OB_PRE_CREATE_CALLBACK, object_hdr->object_type);
		HANDLE_ENTRY* handle_entry = (HANDLE_ENTRY*)HeapAlloc(default_heap, 0x8, sizeof HANDLE_ENTRY);
		if (IsBadPointer(handle_entry)) goto UNLOCK_OBJECT_TYPE;
		else {
			handle_entry->attributes = attributes;
			handle_entry->granted_access_rights = access_rights;
			handle_entry->value = (handle_table->____next_val)++;
			InitializeCriticalSection(&handle_entry->lock);
			EnterCriticalSection(&handle_table->lock);
			WxInsertTailList(&handle_table->handles_list_head, &handle_entry->link);
			LeaveCriticalSection(&handle_table->lock);

			EnterCriticalSection(&object_hdr->lock);
			object_hdr->ref_count++;
			object_hdr->handle_count++;
			LeaveCriticalSection(&object_hdr->lock);

		SET_OUT_HANDLE:
			*out_handle = (WXHANDLE)((((DWORD64)handle_entry->value) << 32) | access_rights);
			handle_entry->object_hdr = object_hdr;
			wx_status = object_hdr->object_type->OnOpen(object_hdr);
			if (WX_SUCCESS(wx_status)) {
				ObCallPostCallbacks(object_hdr, OB_POST_CREATE_CALLBACK, object_hdr->object_type);
				goto UNLOCK_OBJECT_TYPE;
			}
		DELETE_LOCK:
			DeleteCriticalSection(&handle_entry->lock);
		REMOVE_HANDLE_ENTRY:
			WxRemoveFromList(&handle_entry->link);
		FREE_HANDLE_ENTRY:
			HeapFree(default_heap, 0x8, handle_entry);
		}
	}

UNLOCK_OBJECT_TYPE:
	LeaveCriticalSection(&object_hdr->object_type->lock);
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObCreateObject(ULONG type_id, LPCWSTR name, ULONG cch_name, SIZE_T body_size, LPWX_SECURITY_DESCRIPTOR sd, LPOBJECT_HEADER* __object_hdr, ULONG* create_disposition) {
	if (IsBadPointer(__object_hdr) || !body_size) return WXSTATUS_FAILED;

	if (!(type_id & OB_OBJECT_TYPE_MASK)) return WXSTATUS_FAILED;

	if (IsBadPointer(__object_manager)) return WXSTATUS_FAILED;

	EnterCriticalSection(&__object_manager->object_types_lock);

	WXSTATUS wx_status = WXSTATUS_FAILED;

	WX_LIST_ENTRY* type_iterator = __object_manager->object_type_list_head.Flink;
	WX_LIST_ENTRY* type_list_head = &__object_manager->object_type_list_head;

	LPOBJECT_TYPE object_type = 0x0;

	while (type_iterator != type_list_head) {
		object_type = CONTAINING_RECORD(type_iterator, OBJECT_TYPE, link);
		if (!IsBadPointer(object_type) && object_type->type_id == type_id) break;
		type_iterator = type_iterator->Flink;
	}

	if (type_iterator == type_list_head || IsBadPointer(object_type)) goto UNLOCK_OBJECT_TYPES_LIST;
	else {
		HANDLE default_heap = GetProcessHeap();
		if (IsBadPointer(default_heap)) goto UNLOCK_OBJECT_TYPES_LIST;
		else {
			LPOBJECT_HEADER object_hdr = 0x0;
			ULONG disposition = OB_OPENED;

			LPOBJECT_NAME_ENTRY* cracked_name = 0x0;
			ULONG components_count = 0x0, unfound_sub_path_starting_offset = 0x0;
			wx_status = ObLookupGlobalNamespace(name, cch_name, &cracked_name, &components_count, &unfound_sub_path_starting_offset);
			if (WX_SUCCESS(wx_status)) {
				if (!IsBadPointer(cracked_name) && components_count) {
					object_hdr = cracked_name[components_count - 0x1]->object_hdr;
					if (!IsBadPointer(object_hdr)) {
					OBJECT_FOUND:
						if (object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) goto FREE_CRACKED_NAME_ARRAY;
						else {
							wx_status = ObReferenceObject((LPVOID)((UINT_PTR)object_hdr + sizeof _OBJECT_HEADER), 0x0);
							if (WX_SUCCESS(wx_status)) *__object_hdr = object_hdr;
						}
					}
				}
			}
			else {
				disposition = OB_CREATED;
				BOOLEAN b_insert = 0x1;
				LPOBJECT_NAME_ENTRY name_entry = 0x0;
				if (!components_count) wx_status = (!name && !cch_name) ? WXSTATUS_SUCCESS : (type_id == OB_OBJECT_TYPE_OBJECT_DIRECTORY ? ObAllocateNameEntry(name + 0x1, cch_name - 0x1, OB_NAME_ENTRY_FLAG_DIRECTORY, &name_entry, 0x0) :
						WXSTATUS_FAILED);
				else {
					LPOBJECT_NAME_ENTRY parent_node = cracked_name[components_count - 0x1];
					if (parent_node->object_hdr->object_type->type_id == OB_OBJECT_TYPE_OBJECT_DIRECTORY) {
						if (name[unfound_sub_path_starting_offset] == L'\\') {
							BOOLEAN b_nested_path = 0x0;
							for (UINT i = unfound_sub_path_starting_offset + 0x1; i < cch_name; i++) if (name[i] == L'\\') {
								b_nested_path = 0x1;
								break;
							}
							if (!b_nested_path) wx_status = (!name && !cch_name) ? WXSTATUS_SUCCESS : ObAllocateNameEntry(name + unfound_sub_path_starting_offset + 0x1, lstrlenW(name + unfound_sub_path_starting_offset + 0x1),
								0x0, &name_entry, parent_node);
						}
					}
					else {
						object_hdr = parent_node->object_hdr;
						b_insert = 0x0;
						wx_status = (!name && !cch_name) ? WXSTATUS_SUCCESS : ObAllocateNameEntry(name + unfound_sub_path_starting_offset + 0x1, lstrlenW(name + unfound_sub_path_starting_offset + 0x1),
							OB_NAME_ENTRY_FLAG_PRIVATE_ENTRY, &name_entry, 0x0);
						if (WX_SUCCESS(wx_status)) {
							if (!IsBadPointer(name_entry)) {
								WxRemoveFromList(&name_entry->link);
								name_entry->direct_parent = object_hdr->name_entry;
							}
							goto INITIALIZE_OBJECT_HEADER;
						}
					}
				}
				if (!WX_SUCCESS(wx_status)) goto FREE_CRACKED_NAME_ARRAY;
				else {
					object_hdr = (OBJECT_HEADER*)HeapAlloc(default_heap, 0x8, sizeof OBJECT_HEADER + body_size);
					if (IsBadPointer(object_hdr)) goto FREE_NAME_ENTRY;
					else {
						object_hdr->signature = OB_OBJECT_HEADER_SIGNATURE;
						object_hdr->name_entry = name_entry;
						object_hdr->object_type = object_type;
						object_hdr->body_size = body_size;
						InitializeCriticalSection(&object_hdr->lock);
					INITIALIZE_OBJECT_HEADER:
						if (object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) {
							if (b_insert) goto FREE_OBJECT;
							else goto FREE_NAME_ENTRY;
						}
						else {
							wx_status = object_type->OnQueryCreate(object_hdr);
							if (!WX_SUCCESS(wx_status)) {
								if (b_insert) goto FREE_OBJECT;
								else goto FREE_NAME_ENTRY;
							}
							else {
								if (b_insert) WxInsertTailList(&object_type->objects_list_head, &object_hdr->link);
								wx_status = ObReferenceObject((LPVOID)((UINT_PTR)object_hdr + sizeof _OBJECT_HEADER), 0x0);
								if (WX_SUCCESS(wx_status)) {
									wx_status = object_type->OnCreate(object_hdr);
									if (WX_SUCCESS(wx_status)) {
										if (!IsBadPointer(name_entry)) name_entry->object_hdr = object_hdr;
										*__object_hdr = object_hdr;
										goto FREE_CRACKED_NAME_ARRAY;
									}
								}
							}
						}

					FREE_OBJECT:
						if (!IsBadPointer(object_hdr)) HeapFree(default_heap, 0x8, object_hdr);
					}
				FREE_NAME_ENTRY:
					if (!IsBadPointer(name_entry)) {
						HeapFree(default_heap, 0x8, name_entry->name.Buffer);
						HeapFree(default_heap, 0x8, name_entry);
					}
				}
			}

		FREE_CRACKED_NAME_ARRAY:
			if (WX_SUCCESS(wx_status)) {
				if (!IsBadPointer(*__object_hdr)) (*__object_hdr)->security_descriptor = sd;
				if (!IsBadPointer(create_disposition)) *create_disposition = disposition;
			}
			if (!IsBadPointer(cracked_name)) {
				for (UINT i = 0x0; i < components_count; i++) cracked_name[i] = 0x0;
				HeapFree(default_heap, 0x0, cracked_name);
			}
		}
	}

UNLOCK_OBJECT_TYPES_LIST:
	LeaveCriticalSection(&__object_manager->object_types_lock);
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObReferenceObject(LPVOID object_body, ULONG* ref_count) {
	if (IsBadPointer(object_body)) return WXSTATUS_FAILED;

	OBJECT_HEADER* object_hdr = ObGetObjectHeader(object_body);
	if (IsBadPointer(object_hdr) || object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) return WXSTATUS_FAILED;

	EnterCriticalSection(&object_hdr->lock);

	object_hdr->ref_count++;
	if (!IsBadPointer(ref_count)) *ref_count = object_hdr->ref_count;

	LeaveCriticalSection(&object_hdr->lock);

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObDereferenceObject(LPVOID object_body, ULONG* ref_count) {
	if (IsBadPointer(object_body)) return WXSTATUS_FAILED;

	OBJECT_HEADER* object_hdr = ObGetObjectHeader(object_body);
	if (IsBadPointer(object_hdr) || object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_SUCCESS;

	EnterCriticalSection(&object_hdr->lock);

	object_hdr->ref_count--;
	if (!IsBadPointer(ref_count)) *ref_count = object_hdr->ref_count;

	BOOLEAN b_free = 0x0;

	if (!object_hdr->ref_count && object_hdr->handle_count <= 0x0) {
		b_free = 0x1;
		EnterCriticalSection(&object_hdr->object_type->lock);
		wx_status = object_hdr->object_type->OnQueryDelete(object_hdr);
		if (!WX_SUCCESS(wx_status)) goto UNLOCK_OBJECT_TYPE;
		else {
			WxRemoveFromList(&object_hdr->link);
			if (!IsBadPointer(object_hdr->name_entry)) {
				EnterCriticalSection(&object_hdr->name_entry->lock);
				WxRemoveFromList(&object_hdr->name_entry->link);
				LeaveCriticalSection(&object_hdr->name_entry->lock);
				HeapFree(default_heap, 0x0, object_hdr->name_entry->name.Buffer);
				HeapFree(default_heap, 0x0, object_hdr->name_entry);
			}
		}
	UNLOCK_OBJECT_TYPE:
		LeaveCriticalSection(&object_hdr->object_type->lock);
	}

UNLOCK_OBJECT:
	if(WX_SUCCESS(wx_status)) wx_status = object_hdr->object_type->OnDelete(object_hdr);
	LeaveCriticalSection(&object_hdr->lock);
EPILOGUE:
	if (WX_SUCCESS(wx_status) && b_free) HeapFree(default_heap, 0x8, object_hdr);
	return wx_status;
}

WXSTATUS __stdcall ObMakeObjectParmanent(LPVOID object_body) {
	return ObReferenceObject(object_body, 0x0);
}

WXSTATUS __stdcall ObMakeObjectTemporary(LPVOID object_body) {
	return ObDereferenceObject(object_body, 0x0);
}

WXSTATUS __stdcall ObLookupGlobalNamespace(LPCWSTR name, ULONG cch_name, LPOBJECT_NAME_ENTRY** name_components, ULONG* components_count, ULONG* unfound_sub_path_starting_offset) {
	if (!name || IsBadPointer(name_components) || cch_name < 0x2) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	EnterCriticalSection(&__object_manager->namespace_lock);

	LPOBJECT_HEADER object_hdr = 0x0;
	WXSTATUS wx_status = WXSTATUS_SUCCESS;
	ULONG iterator = 0x0, entries_count = 0x0, i = 0x0;
	SIZE_T array_buf_size = 0x0;
	do {
	PARSING_LOOP:
		if ((iterator + 0x1) >= cch_name || name[iterator] != L'\\') goto EPILOGUE;
		else {
			if(!array_buf_size) *name_components = (LPOBJECT_NAME_ENTRY*)HeapAlloc(default_heap, 0x8, array_buf_size + 0x8);
			else *name_components = (LPOBJECT_NAME_ENTRY*)HeapReAlloc(default_heap, 0x8, *name_components, array_buf_size + 0x8);
			
			if (IsBadPointer(*name_components)) goto EPILOGUE;
			else {
				WX_LIST_ENTRY* start_head = 0x0;
				if (i == 0x0) start_head = &__object_manager->namespace_root;
				else start_head = &(*name_components)[i - 0x1]->direct_children_list_head;
				if (start_head && !IsBadPointer(start_head)) {
					if (i != 0x0) EnterCriticalSection(&(*name_components)[i - 0x1]->lock);
					WX_LIST_ENTRY* entry_iterator = start_head->Flink;
					LPOBJECT_NAME_ENTRY name_entry = 0x0;
					while (entry_iterator != start_head) {
						name_entry = CONTAINING_RECORD(entry_iterator, OBJECT_NAME_ENTRY, link);
						if (!IsBadPointer(name_entry)) {
							BOOLEAN b_match = 0x0;
							EnterCriticalSection(&name_entry->lock);
							if (name_entry->name.Length <= (lstrlenW(name + iterator + 0x1) * 0x2) && !IsBadPointer(name_entry->name.Buffer) &&
								cmp((LPBYTE)name + (iterator + 0x1) * 0x2, (LPBYTE)name_entry->name.Buffer, name_entry->name.Length)) b_match = 0x1;
							LeaveCriticalSection(&name_entry->lock);
							if (b_match) break;
						}
						entry_iterator = entry_iterator->Flink;
					}
					if (i != 0x0) LeaveCriticalSection(&(*name_components)[i - 0x1]->lock);
					if (entry_iterator != start_head && name_entry) {
						if (!(name_entry->flags & OB_NAME_ENTRY_FLAG_SYMBOLIC_LINK)) object_hdr = name_entry->object_hdr;

						for ((*name_components)[i] = name_entry; !IsBadPointer((*name_components)[i]) && ((*name_components)[i]->flags & OB_NAME_ENTRY_FLAG_SYMBOLIC_LINK);
							(*name_components)[i] = (*name_components)[i]->link_target);

						if (!IsBadPointer((*name_components)[i])) {
							i++; entries_count++;
							iterator += (name_entry->name.Length / 0x2 + 0x1);
							array_buf_size += 0x8;
							goto PARSING_LOOP;
						}
					}
				}
			}
		}
	CLEANUP:
		wx_status = IsBadPointer(object_hdr) || object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE ? WXSTATUS_NOT_FOUND : 
			object_hdr->object_type->LookupPrivateNamespace(object_hdr, name + iterator, lstrlenW(name + iterator));
		if (!WX_SUCCESS(wx_status) && !IsBadPointer(unfound_sub_path_starting_offset)) *unfound_sub_path_starting_offset = iterator;
		goto EPILOGUE;
	} while (	TRUE  );

EPILOGUE:
	LeaveCriticalSection(&__object_manager->namespace_lock);
	if (!IsBadPointer(components_count)) *components_count = entries_count;
	return wx_status;
}

LPOBJECT_HEADER __stdcall ObGetObjectHeader(LPVOID object_body) {
	if (IsBadPointer(object_body)) return 0x0;
	return (LPOBJECT_HEADER)((UINT_PTR)object_body - sizeof OBJECT_HEADER);
}

WXSTATUS __stdcall ObLookupHandleTable(HANDLE_TABLE* handle_table, WXHANDLE wxhandle, LPHANDLE_ENTRY* handle_entry) {
	if (IsBadPointer(handle_entry)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_NOT_FOUND;

	EnterCriticalSection(&handle_table->lock);

	ULONG __val = (ULONG)(((ULONG_PTR)wxhandle) >> 32);
	LPHANDLE_ENTRY __handle_entry = 0x0;

	WX_LIST_ENTRY* iterator = handle_table->handles_list_head.Flink;
	WX_LIST_ENTRY* head = &handle_table->handles_list_head;

	while (iterator != head) {
		__handle_entry = CONTAINING_RECORD(iterator, HANDLE_ENTRY, link);
		if (!IsBadPointer(__handle_entry) && __handle_entry->value == __val) break;
		iterator = iterator->Flink;
	}

	wx_status = iterator != head ? WXSTATUS_SUCCESS : WXSTATUS_FAILED;

UNLOCK_HANDLE_TABLE:
	LeaveCriticalSection(&handle_table->lock);
EPILOGUE:
	if (WX_SUCCESS(wx_status) && !IsBadPointer(handle_table)) *handle_entry = __handle_entry;
	return wx_status;
}

WXSTATUS __stdcall ObCloseHandle(WXHANDLE wx_handle, KPROCESSOR_MODE processor_mode) {
	if (IsBadPointer(__object_manager)) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	HANDLE_TABLE* handle_table = processor_mode == KERNEL_MODE ? __object_manager->kernel_handle_table : __object_manager->user_handle_table;
	if (IsBadPointer(handle_table)) return WXSTATUS_FAILED;

	LPHANDLE_ENTRY handle_entry = 0x0;
	WXSTATUS wx_status = ObLookupHandleTable(handle_table, wx_handle, &handle_entry);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(handle_entry)) goto EPILOGUE;
	else {
		EnterCriticalSection(&handle_entry->lock);
		if (processor_mode == USER_MODE && (handle_entry->attributes & OB_HANDLE_ATTRIBUTE_KERNEL)) goto UNLOCK_HANDLE_ENTRY;
		else if (!IsBadPointer(handle_entry->object_hdr) && handle_entry->object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) {
			wx_status = handle_entry->object_hdr->object_type->OnQueryClose(handle_entry->object_hdr);
			if (!WX_SUCCESS(wx_status)) goto UNLOCK_HANDLE_ENTRY;
			else {
				ObCallPreCallbacks(handle_entry->object_hdr, OB_PRE_DELETE_CALLBACK, handle_entry->object_hdr->object_type);
				EnterCriticalSection(&handle_entry->object_hdr->lock);
				if (handle_entry->object_hdr->handle_count <= 0x0) goto CLEANUP;
				else {
					handle_entry->object_hdr->handle_count--;
					if (!handle_entry->object_hdr->handle_count) {
						if (!IsBadPointer(handle_entry->object_hdr->name_entry)) {
							EnterCriticalSection(&handle_entry->object_hdr->name_entry->lock);

							CRITICAL_SECTION* lock = 0x0;

							if (!handle_entry->object_hdr->name_entry->direct_parent) lock = &__object_manager->namespace_lock;
							else lock = &handle_entry->object_hdr->name_entry->direct_parent->lock;

							if (lock) {
								EnterCriticalSection(lock);
								WxRemoveFromList(&handle_entry->object_hdr->name_entry->link);
								LeaveCriticalSection(lock);
							}

							if (!IsBadPointer(handle_entry->object_hdr->name_entry->name.Buffer))
								HeapFree(default_heap, 0x8, handle_entry->object_hdr->name_entry->name.Buffer);

							LeaveCriticalSection(&handle_entry->object_hdr->name_entry->lock);

							HeapFree(default_heap, 0x8, handle_entry->object_hdr->name_entry);
						}
						handle_entry->object_hdr->name_entry = 0x0;
					}
				}

			CLEANUP:
				wx_status = handle_entry->object_hdr->object_type->OnClose(handle_entry->object_hdr);
				if (WX_SUCCESS(wx_status)) {
					ObCallPostCallbacks(handle_entry->object_hdr, OB_POST_DELETE_CALLBACK, handle_entry->object_hdr->object_type);
					ObDereferenceObject((LPVOID)((UINT_PTR)handle_entry->object_hdr + sizeof _OBJECT_HEADER), 0x0);
					HeapFree(default_heap, 0x8, handle_entry);
				}

			}
		}
	UNLOCK_HANDLE_ENTRY:
		LeaveCriticalSection(&handle_entry->lock);
	}
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObReferenceObjectByHandle(WXHANDLE wxhandle, KPROCESSOR_MODE processor_mode, LPOBJECT_TYPE object_type, WX_ACCESS_MASK access_rights, LPVOID* object_body) {
	if (IsBadPointer(object_body)) return WXSTATUS_FAILED;

	HANDLE_TABLE* handle_table = processor_mode == USER_MODE ? __object_manager->user_handle_table : __object_manager->kernel_handle_table;
	if (IsBadPointer(handle_table)) return WXSTATUS_FAILED;

	LPHANDLE_ENTRY handle_entry = 0x0;
	WXSTATUS wx_status = ObLookupHandleTable(handle_table, wxhandle, &handle_entry);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(handle_entry)) goto EPILOGUE;
	else {
		EnterCriticalSection(&handle_entry->lock);
		if (!IsBadPointer(handle_entry->object_hdr) && handle_entry->object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE && (!object_type || object_type == handle_entry->object_hdr->object_type)) {
			EnterCriticalSection(&handle_entry->object_hdr->lock);
			wx_status = handle_entry->object_hdr->object_type->OnQueryCreate(handle_entry->object_hdr);
			LeaveCriticalSection(&handle_entry->object_hdr->lock);
			if (WX_SUCCESS(wx_status)) {
				wx_status = ObReferenceObject((LPVOID)((UINT_PTR)handle_entry->object_hdr + sizeof _OBJECT_HEADER), 0x0);
				if (WX_SUCCESS(wx_status)) {
					EnterCriticalSection(&handle_entry->object_hdr->lock);
					wx_status = handle_entry->object_hdr->object_type->OnCreate(handle_entry->object_hdr);
					LeaveCriticalSection(&handle_entry->object_hdr->lock);
					if (WX_SUCCESS(wx_status)) *object_body = (LPVOID)((UINT_PTR)handle_entry->object_hdr + sizeof _OBJECT_HEADER);
				}
			}
		}
		else wx_status = WXSTATUS_FAILED;
	UNLOCK_HANDLE_ENTRY:
		LeaveCriticalSection(&handle_entry->lock);
	}

EPILOGUE:
	return wx_status;
}

BOOLEAN __stdcall ObIsKernelHandle(WXHANDLE wx_handle) {
	LPHANDLE_ENTRY handle_entry = 0x0;
	WXSTATUS wx_status = ObLookupHandleTable(__object_manager->kernel_handle_table, wx_handle, &handle_entry);
	return WX_SUCCESS(wx_status) && (handle_entry->attributes & OB_HANDLE_ATTRIBUTE_KERNEL);
}

WXSTATUS __stdcall ObDuplicateHandle(WXHANDLE src_handle, HANDLE_TABLE* target_handle_table, WX_ACCESS_MASK access_rights, WXHANDLE* duplicate_handle) {
	if (IsBadPointer(target_handle_table)) return WXSTATUS_FAILED;

	LPHANDLE_ENTRY handle_entry = 0x0;
	WXSTATUS wx_status = ObLookupHandleTable(__object_manager->kernel_handle_table, src_handle, &handle_entry);
	if(!WX_SUCCESS(wx_status)) wx_status = ObLookupHandleTable(__object_manager->user_handle_table, src_handle, &handle_entry);

	if (!WX_SUCCESS(wx_status) || IsBadPointer(handle_entry)) return wx_status;


	EnterCriticalSection(&handle_entry->lock);

	if ((handle_entry->attributes & OB_HANDLE_ATTRIBUTE_KERNEL) && target_handle_table != __object_manager->kernel_handle_table) goto UNLOCK_HANDLE_ENTRY;
	else {
		ObCallPreCallbacks(handle_entry->object_hdr, OB_PRE_DUPLICATE_CALLBACK, handle_entry->object_hdr->object_type);
		wx_status = ObCreateHandle(target_handle_table, (LPVOID)((UINT_PTR)handle_entry->object_hdr + sizeof _OBJECT_HEADER), handle_entry->attributes,
			access_rights != WX_INVALID_ACCESS_RIGHT ? (access_rights & handle_entry->granted_access_rights) : handle_entry->granted_access_rights, duplicate_handle);
	}

UNLOCK_HANDLE_ENTRY:
	LeaveCriticalSection(&handle_entry->lock);
EPILOGUE:
	if(WX_SUCCESS(wx_status)) ObCallPostCallbacks(handle_entry->object_hdr, OB_POST_DUPLICATE_CALLBACK, handle_entry->object_hdr->object_type);
	return wx_status;
}

WXSTATUS __stdcall ObRegisterCallback(ULONG type_id, ULONG callback_type, ObCallback callback_routine, ULONG_PTR callback_routine_context, WX_LIST_ENTRY** callback_link) {
	if (IsBadPointer(callback_routine) || ((INT)callback_type) < 0x0 || callback_type > 0x5) return WXSTATUS_FAILED;

	LPOBJECT_CALLBACK callback_obj = (LPOBJECT_CALLBACK)HeapAlloc(GetProcessHeap(), 0x8, sizeof _OBJECT_CALLBACK);
	if (IsBadPointer(callback_obj)) return WXSTATUS_FAILED;

	WX_LIST_ENTRY* type_iterator = __object_manager->object_type_list_head.Flink;
	WX_LIST_ENTRY* type_list_head = &__object_manager->object_type_list_head;

	WXSTATUS wx_status = WXSTATUS_FAILED;
	LPOBJECT_TYPE object_type = 0x0;

	while (type_iterator != type_list_head) {
		object_type = CONTAINING_RECORD(type_iterator, OBJECT_TYPE, link);
		if (!IsBadPointer(object_type) && object_type->type_id == type_id) break;
		type_iterator = type_iterator->Flink;
	}

	if (type_iterator == type_list_head || IsBadPointer(object_type)) goto EPILOGUE;
	else {
		callback_obj->callback_routine = callback_routine;
		callback_obj->callback_routine_context = callback_routine_context;
		callback_obj->object_type = object_type;
		callback_obj->type = callback_type;

		if (!IsBadPointer(callback_link)) *callback_link = &callback_obj->link;

		EnterCriticalSection(&__object_manager->callback_locks[callback_type]);
		WxInsertTailList(&__object_manager->ob_callbacks[callback_type], &callback_obj->link);
		LeaveCriticalSection(&__object_manager->callback_locks[callback_type]);

		wx_status = WXSTATUS_SUCCESS;
	}

EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall ObUnregisterCallback(WX_LIST_ENTRY* callback_link) {
	if (IsBadPointer(callback_link)) return WXSTATUS_FAILED;

	LPOBJECT_CALLBACK callback_obj = CONTAINING_RECORD(callback_link, OBJECT_CALLBACK, link);
	if (IsBadPointer(callback_obj) || ((INT)callback_obj->type < 0x0) || callback_obj->type > 0x5) return WXSTATUS_FAILED;

	EnterCriticalSection(&__object_manager->callback_locks[callback_obj->type]);
	WxRemoveFromList(callback_link);
	LeaveCriticalSection(&__object_manager->callback_locks[callback_obj->type]);

	HeapFree(GetProcessHeap(), 0x8, callback_obj);

	return WXSTATUS_SUCCESS;
}

void __stdcall ObCallPreCallbacks(LPOBJECT_HEADER object_hdr, ULONG callback_type, LPOBJECT_TYPE object_type) {
	if (IsBadPointer(object_hdr) || ((INT)callback_type) < 0x0 || callback_type > 0x2) return;

	EnterCriticalSection(&__object_manager->callback_locks[callback_type]);
	
	WX_LIST_ENTRY* head = &__object_manager->ob_callbacks[callback_type];
	WX_LIST_ENTRY* iterator = head->Flink;

	while (iterator != head) {
		LPOBJECT_CALLBACK callback_obj = CONTAINING_RECORD(iterator, OBJECT_CALLBACK, link);
		if (!IsBadPointer(callback_obj) && !IsBadPointer(callback_obj->callback_routine) && (!object_type || callback_obj->object_type->type_id == object_type->type_id) && 
			callback_obj->type == callback_type)
			callback_obj->callback_routine(object_hdr, callback_obj->callback_routine_context);
		iterator = iterator->Flink;
	}

	LeaveCriticalSection(&__object_manager->callback_locks[callback_type]);
}

void __stdcall ObCallPostCallbacks(LPOBJECT_HEADER object_hdr, ULONG callback_type, LPOBJECT_TYPE object_type) {
	if (IsBadPointer(object_hdr) || ((INT)callback_type) < 0x3 || callback_type > 0x5) return;

	EnterCriticalSection(&__object_manager->callback_locks[callback_type]);

	WX_LIST_ENTRY* head = &__object_manager->ob_callbacks[callback_type];
	WX_LIST_ENTRY* iterator = head->Flink;

	while (iterator != head) {
		LPOBJECT_CALLBACK callback_obj = CONTAINING_RECORD(iterator, OBJECT_CALLBACK, link);
		if (!IsBadPointer(callback_obj) && !IsBadPointer(callback_obj->callback_routine) && (!object_type || callback_obj->object_type->type_id == object_type->type_id) && 
			callback_obj->type == callback_type)
			callback_obj->callback_routine(object_hdr, callback_obj->callback_routine_context);
		iterator = iterator->Flink;
	}

	LeaveCriticalSection(&__object_manager->callback_locks[callback_type]);
}

WXSTATUS __stdcall ObOpenObjectByName(LPCWSTR name, ULONG cch_name, KPROCESSOR_MODE processor_mode, ULONG attributes, WX_ACCESS_MASK access_rights, WXHANDLE* out_handle) {
	if (!name || !cch_name || IsBadPointer(out_handle)) return WXSTATUS_FAILED;

	LPOBJECT_NAME_ENTRY* cracked_name = 0x0;
	ULONG components_count = 0x0;
	
	WXSTATUS wx_status = ObLookupGlobalNamespace(name, cch_name, &cracked_name, &components_count, 0x0);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(cracked_name) || !components_count) return wx_status;

	LPOBJECT_NAME_ENTRY name_entry = cracked_name[components_count - 0x1];
	if (IsBadPointer(name_entry) || IsBadPointer(name_entry->object_hdr) || name_entry->object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) return WXSTATUS_FAILED;

	wx_status = ObCreateHandle(processor_mode == USER_MODE ? __object_manager->user_handle_table : __object_manager->kernel_handle_table,
		(LPVOID)((UINT_PTR)name_entry->object_hdr + sizeof _OBJECT_HEADER), processor_mode == USER_MODE ? attributes : (attributes | OB_HANDLE_ATTRIBUTE_KERNEL),
		access_rights, out_handle);

	return wx_status;
}

WXSTATUS __stdcall ObOpenObjectByPointer(LPVOID object_pointer, KPROCESSOR_MODE processor_mode, ULONG attributes, WX_ACCESS_MASK access_rights, WXHANDLE* out_handle) {
	if (IsBadPointer(out_handle) || IsBadPointer(object_pointer)) return WXSTATUS_FAILED;

	LPOBJECT_HEADER object_hdr = ObGetObjectHeader(object_pointer);
	if (IsBadPointer(object_hdr)) return WXSTATUS_FAILED;

	if (object_hdr->signature != OB_OBJECT_HEADER_SIGNATURE) return WXSTATUS_FAILED;

	return ObCreateHandle(processor_mode == USER_MODE ? __object_manager->user_handle_table : __object_manager->kernel_handle_table, object_pointer,
		processor_mode == USER_MODE ? attributes : (attributes | OB_HANDLE_ATTRIBUTE_KERNEL), access_rights, out_handle);
}

WXSTATUS __stdcall ObGetObjectName(WXHANDLE wx_handle, LPWSTR* out_name, ULONG* out_cch_name) {
	if (IsBadPointer(out_name)) return WXSTATUS_FAILED;

	LPVOID object_body = 0x0;
	WXSTATUS wx_status = ObReferenceObjectByHandle(wx_handle, USER_MODE, 0x0, 0x0, &object_body);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(object_body)) return wx_status;

	LPOBJECT_HEADER object_hdr = ObGetObjectHeader(object_body);
	if (IsBadPointer(object_hdr)) return WXSTATUS_FAILED;

	if (IsBadPointer(object_hdr->name_entry)) return WXSTATUS_FAILED;

	EnterCriticalSection(&object_hdr->name_entry->lock);

	if (!IsBadPointer(out_name)) *out_name = object_hdr->name_entry->name.Buffer;

	LeaveCriticalSection(&object_hdr->name_entry->lock);

	if (!IsBadPointer(*out_name)) {
		wx_status = WXSTATUS_SUCCESS;
		if (!IsBadPointer(out_cch_name)) *out_cch_name = (object_hdr->name_entry->name.Length / 0x2);
	}

	return wx_status;
}

WXSTATUS __stdcall ObpOnQueryCreate(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnCreate(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnQueryOpen(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnOpen(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnQueryClose(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnClose(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnQueryDelete(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpOnDelete(OBJECT_HEADER* object_hdr) {
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall ObpLookupPrivateNamespace(OBJECT_HEADER* object_hdr, LPCWSTR name, ULONG cch_name) {
	return WXSTATUS_NOT_FOUND;
}

WXSTATUS __stdcall ObMapGenericAccessRights(OBJECT_TYPE* object_type, WX_ACCESS_MASK generic_rights, WX_ACCESS_MASK* specific_rights) {
	if (!IsBadPointer(specific_rights)) *specific_rights = (generic_rights & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL));
	return WXSTATUS_SUCCESS;
}

// ========================= SECURITY REFERENCE MONITOR ============================

WXSTATUS __stdcall SeInitializeWxSecurityReferenceMonitor() {
	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	srm_manager.sam_database = (LPWX_SECURITY_ACCOUNT_MANAGER_DATABASE)HeapAlloc(default_heap, 0x8, sizeof WX_SECURITY_ACCOUNT_MANAGER_DATABASE);
	if (IsBadPointer(srm_manager.sam_database)) return WXSTATUS_FAILED;

	LPOBJECT_TYPE token_object_type = 0x0;
	WXSTATUS wx_status = ObCreateObjectType(OB_OBJECT_TYPE_ACCESS_TOKEN, (TOKEN_ALL_ACCESS | SE_COMMON_RIGHTS) & ~SYNCHRONIZE, &token_object_type);
	if (!WX_SUCCESS(wx_status)) goto FREE_SAM_DATABASE;
	else {
		token_object_type->ObGenericAccessRightsMapper = (ObAccessRightsMappingRoutine)SeAccessTokenMapGenericAccessRights;

		InitializeCriticalSection(&srm_manager.lock);
		InitializeCriticalSection(&srm_manager.sam_database->lock);

		WxInitializeListHead(&srm_manager.sam_database->account_list_head);
		WxInitializeListHead(&srm_manager.valid_privileges);

		// ============================== PRIVILEGES ===============================

		SeCreatePrivilege(L"SeAssignPrimaryTokenPrivilege", 29, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeAuditPrivilege", 16, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeBackupPrivilege", 17, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeChangeNotifyPrivilege", 23, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeCreateGlobalPrivilege", 23, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeCreatePagefilePrivilege", 25, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeCreatePermanentPrivilege", 26, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeCreateSymbolicLinkPrivilege", 29, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeCreateTokenPrivilege", 22, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeEnableDelegationPrivilege", 27, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeImpersonatePrivilege", 22, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeIncreaseBasePriorityPrivilege", 31, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeIncreaseQuotaPrivilege", 24, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeIncreaseWorkingSetPrivilege", 29, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeLoadDriverPrivilege", 21, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeLockMemoryPrivilege", 21, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeMachineAccountPrivilege", 25, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeManageVolumePrivilege", 23, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeProfileSingleProcessPrivilege", 31, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeRelabelPrivilege", 18, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeRemoteShutdownPrivilege", 25, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeRestorePrivilege", 18, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeSecurityPrivilege", 19, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeShutdownPrivilege", 19, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeSyncAgentPrivilege", 20, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeSystemEnvironmentPrivilege", 28, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeSystemProfilePrivilege", 24, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeSystemTimePrivilege", 21, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeTakeOwnershipPrivilege", 24, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeTcbPrivilege", 14, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeTimeZonePrivilege", 19, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeTrustedCredManAccessPrivilege", 31, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeUnlockPrivilege", 17, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeUnsolicitedInputPrivilege", 27, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeDebugPrivilege", 16, 0x0, 0x0, 0x0);
		SeCreatePrivilege(L"SeDelegateSessionUserImpersonatePrivilege", 41, 0x0, 0x0, 0x0);

		// ============================= ACCOUNTS ==============================

		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, computer_name, lstrlenW(computer_name), 0x0, 0x0, SE_ACCOUNT_TYPE_COMPUTER, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_WORLD_SID_AUTHORITY, L"World", 0x5, 0x0, 0x0, SE_ACCOUNT_TYPE_GROUP, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, L"Admin", 0x5, 0x0, 0x0, SE_ACCOUNT_TYPE_GROUP, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, L"SYSTEM", 0x6, 0x0, 0x0, SE_ACCOUNT_TYPE_SERVICE, 0x0, 0x0, 0x0, 0xFFFFFFFF, SE_SYSTEM_INTEGRITY_LEVEL, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, L"LocalService", 0xC, 0x0, 0x0, SE_ACCOUNT_TYPE_SERVICE, 0x0, 0x0, 0x0, 0x0, SE_SYSTEM_INTEGRITY_LEVEL, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, L"LocalNetwork", 0xC, 0x0, 0x0, SE_ACCOUNT_TYPE_SERVICE, 0x0, 0x0, 0x0, 0x0, SE_SYSTEM_INTEGRITY_LEVEL, 0x0, 0x0);
		SeCreateAccount(SE_SECURITY_NT_AUTHORITY, default_user_name, lstrlenW(default_user_name), 0x0, 0x0, SE_ACCOUNT_TYPE_USER, 0x0, 0x0, 0x0, 0x0, SE_MEDIUM_INTEGRITY_LEVEL, 0x0, 0x0);

		// ============================================================

		goto EPILOGUE;
	}
DELETE_SAM_DATABASE_LOCK:
	DeleteCriticalSection(&srm_manager.sam_database->lock);
FREE_SAM_DATABASE:
	HeapFree(default_heap, 0x8, srm_manager.sam_database);
EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall SeCreateAccount(WX_SECRURITY_AUTHORITY auth, LPCWSTR name, ULONG cch_name, LPBYTE pwd_hash, ULONG pwd_hash_size, ULONG account_type, LPWX_ACCOUNT* groups, ULONG groups_count, LPCWSTR* privileges, ULONG privileges_count, ULONG integrity_level, LPWX_ACCOUNT* out_account, ULONG* create_disposition) {
	if (!SeIsValidAccountName(name, cch_name) || auth < 0x1 || auth > 0x7) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	EnterCriticalSection(&srm_manager.sam_database->lock);

	LPWX_ACCOUNT account = 0x0;
	WXSTATUS wx_status = SeLookupAccountByName(name, cch_name, &account);

	if (WX_SUCCESS(wx_status) && !IsBadPointer(account)) {
		if (!IsBadPointer(out_account)) *out_account = account;
		if (!IsBadPointer(create_disposition)) *create_disposition = SE_OPENED;
		return WXSTATUS_SUCCESS;
	}

	LPWX_SID account_sid = 0x0;
	ULONG sid_attributes = account_type == SE_ACCOUNT_TYPE_GROUP ? SE_SID_GROUP : SE_SID_USER;
	sid_attributes |= SE_SID_ENABLED;
	wx_status = SeAllocateAndInitializeSid(auth, sid_attributes, &account_sid);

	if (!WX_SUCCESS(wx_status) || IsBadPointer(account_sid)) return WXSTATUS_FAILED;

	account = (LPWX_ACCOUNT)HeapAlloc(default_heap, 0x8, sizeof _WX_ACCOUNT);
	if (IsBadPointer(account)) return WXSTATUS_FAILED;

	account->name.Buffer = (LPWSTR)HeapAlloc(default_heap, 0x8, cch_name * 0x2 + 0x2);
	if (IsBadPointer(account->name.Buffer)) {
		HeapFree(default_heap, 0x8, account);
		return WXSTATUS_FAILED;
	}
	if (pwd_hash_size) {
		account->pwd = (LPHASHED_PASSWORD)HeapAlloc(default_heap, 0x8, sizeof _HASHED_PASSWORD + pwd_hash_size);
		if (IsBadPointer(account->pwd)) {
			HeapFree(default_heap, 0x8, account->name.Buffer);
			HeapFree(default_heap, 0x8, account);
			return WXSTATUS_FAILED;
		}
		account->pwd->size = sizeof _HASHED_PASSWORD + pwd_hash_size;
		CopyMemory(account->pwd + 0x1, pwd_hash, pwd_hash_size);
	}
	
	account->name.Length = (cch_name * 0x2);
	account->name.MaximumLength = account->name.Length + 0x2;
	CopyMemory(account->name.Buffer, name, account->name.Length);

	if(account_type == SE_ACCOUNT_TYPE_USER || account_type == SE_ACCOUNT_TYPE_SERVICE) account->integrity_level.level = integrity_level;
	account->type = account_type;
	
	InitializeCriticalSection(&account->lock);
	WxInitializeListHead(&account->group_list_head);
	WxInitializeListHead(&account->privilege_list_head);

	if (!IsBadPointer(groups) && groups_count) for (UINT i = 0x0; i < groups_count; i++) WxInsertTailList(&account->group_list_head, &groups[i]->link);
	if (privileges_count == 0xFFFFFFFF) {
		EnterCriticalSection(&srm_manager.lock);
		
		WX_LIST_ENTRY* privilege_iterator = srm_manager.valid_privileges.Flink;
		WX_LIST_ENTRY* head = &srm_manager.valid_privileges;
		while (privilege_iterator != head) {
			LPWX_PRIVILEGE __privilege = CONTAINING_RECORD(privilege_iterator, WX_PRIVILEGE, link);
			if (!IsBadPointer(__privilege) && !IsBadPointer(__privilege->name.Buffer) && __privilege->name.Length) {
				ULONG create_disposition = 0x0;
				WXSTATUS status = SeCreatePrivilege(__privilege->name.Buffer, __privilege->name.Length / 0x2, 0x0, &__privilege, &create_disposition);
				if (WX_SUCCESS(status) && create_disposition == SE_OPENED && !IsBadPointer(__privilege)) WxInsertTailList(&account->privilege_list_head, &__privilege->link);
			}
			privilege_iterator = privilege_iterator->Flink;
		}

		LeaveCriticalSection(&srm_manager.lock);
	}
	else if (!IsBadPointer(privileges) && privileges_count) {
		for (UINT i = 0x0; i < privileges_count; i++) {
			LPWX_PRIVILEGE privilege = 0x0;
			ULONG create_disposition = 0x0;
			WXSTATUS status = SeCreatePrivilege(privileges[i], lstrlenW(privileges[i]), 0x0, &privilege, &create_disposition);
			if (WX_SUCCESS(status) && create_disposition == SE_OPENED && !IsBadPointer(privilege)) WxInsertTailList(&account->privilege_list_head, &privilege->link);
		}
	}

	EnterCriticalSection(&srm_manager.sam_database->lock);
	WxInsertTailList(&srm_manager.sam_database->account_list_head, &account->link);
	srm_manager.sam_database->accounts_count++;
	LeaveCriticalSection(&srm_manager.sam_database->lock);

	account->sid = account_sid;

	if (!IsBadPointer(out_account)) *out_account = account;
	if (!IsBadPointer(create_disposition)) *create_disposition = SE_CREATED;

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeCreatePrivilege(LPCWSTR name, ULONG cch_name, DWORD attributes, LPWX_PRIVILEGE* out_privilege, ULONG* create_disposition) {
	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;
	
	LPWX_PRIVILEGE privilege = (LPWX_PRIVILEGE)HeapAlloc(default_heap, 0x8, sizeof _WX_PRIVILEGE);
	if (IsBadPointer(privilege)) return WXSTATUS_FAILED;

	WX_LIST_ENTRY* privilege_iterator = srm_manager.valid_privileges.Flink;
	WX_LIST_ENTRY* head = &srm_manager.valid_privileges;

	LPWX_PRIVILEGE __privilege = 0x0;
	ULONG __create_disposition = SE_CREATED;

	while (privilege_iterator != head) {
		__privilege = CONTAINING_RECORD(privilege_iterator, WX_PRIVILEGE, link);
		if (!IsBadPointer(__privilege) && !IsBadPointer(__privilege->name.Buffer) && __privilege->name.Length == (cch_name * 0x2) && cmp((LPBYTE)__privilege->name.Buffer,
			(LPBYTE)name, __privilege->name.Length)) break;
		privilege_iterator = privilege_iterator->Flink;
	}

	privilege->name.Buffer = (LPWSTR)HeapAlloc(default_heap, 0x8, cch_name * 0x2);
	if (IsBadPointer(privilege->name.Buffer)) {
		HeapFree(default_heap, 0x8, privilege);
		return WXSTATUS_FAILED;
	}

	if (privilege_iterator != head) {
		__create_disposition = SE_OPENED;
		if (!IsBadPointer(__privilege)) {
			privilege->attributes = __privilege->attributes;
			privilege->id = __privilege->id;
		}
	}
	else {
		privilege->attributes = attributes;
		EnterCriticalSection(&srm_manager.lock);
		privilege->id = srm_manager.__next_luid[0x0];
		if (srm_manager.__next_luid[0x0].low_part == 0xFFFFFFFF) {
			srm_manager.__next_luid[0x0].low_part = 0x0;
			srm_manager.__next_luid[0x0].high_part++;
		}
		else srm_manager.__next_luid[0x0].low_part++;
		WxInsertTailList(&srm_manager.valid_privileges, &privilege->link);
		LeaveCriticalSection(&srm_manager.lock);
	}

	privilege->name.Length = cch_name * 0x2;
	privilege->name.MaximumLength = privilege->name.Length + 0x2;
	CopyMemory(privilege->name.Buffer, name, privilege->name.Length);

	InitializeCriticalSection(&privilege->lock);

	if (!IsBadPointer(out_privilege)) *out_privilege = privilege;
	if (!IsBadPointer(create_disposition)) *create_disposition = __create_disposition;

	return WXSTATUS_FAILED;
}

WXSTATUS __stdcall SeAllocateAndInitializeSid(WX_SECRURITY_AUTHORITY auth, DWORD attributes, LPWX_SID* out_sid) {
	if (auth < 0x1 || auth > 0x7) return WXSTATUS_FAILED;
	
	LPWX_SID sid = (LPWX_SID)HeapAlloc(GetProcessHeap(), 0x8, sizeof _WX_SID);
	if (IsBadPointer(sid)) return WXSTATUS_FAILED;

	sid->auth = auth;
	sid->attributes = attributes;
	InitializeCriticalSection(&sid->lock);

	EnterCriticalSection(&srm_manager.lock);
	sid->id = srm_manager.__next_luid[0x1];
	if (srm_manager.__next_luid[0x1].low_part == 0xFFFFFFFF) {
		srm_manager.__next_luid[0x1].low_part = 0x0;
		srm_manager.__next_luid[0x1].high_part++;
	}
	else srm_manager.__next_luid[0x1].low_part++;
	LeaveCriticalSection(&srm_manager.lock);

	if (!IsBadPointer(out_sid)) *out_sid = sid;
}

WXSTATUS __stdcall SeDuplicateSid(LPWX_SID src_sid, LPWX_SID* out_sid) {
	if (IsBadPointer(src_sid)) return WXSTATUS_FAILED;

	LPWX_SID sid = (LPWX_SID)HeapAlloc(GetProcessHeap(), 0x8, sizeof WX_SID);
	if (IsBadPointer(sid)) return WXSTATUS_FAILED;

	EnterCriticalSection(&src_sid->lock);
	CopyMemory(sid, src_sid, sizeof WX_SID);
	LeaveCriticalSection(&src_sid->lock);
	
	InitializeCriticalSection(&sid->lock);

	if (!IsBadPointer(out_sid)) *out_sid = sid;
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeAllocateAndInitializeAccessToken(LPWX_ACCOUNT account, ULONG token_type, WX_IMPERSONATION_LEVEL impersonation_level, LPWX_SID default_owner, LPWX_SID default_group, LPWX_ACCESS_TOKEN* out_access_token) {
	if (IsBadPointer(account) || IsBadPointer(default_owner) || (token_type != SE_PRIMARY_ACCESS_TOKEN && 
		token_type != SE_IMPERSONATION_ACCESS_TOKEN)) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	PWX_ACCESS_CONTROL_LIST dacl = 0x0;
	WXSTATUS wx_status = SeAllocateAndIitializeAcl(SE_ACL_TYPE_DISCRITIONARY, &dacl);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(dacl)) goto EPILOGUE;
	else {
		SeAddAceToAcl(dacl, SE_ACE_TYPE_ALLOW, account->sid, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_SESSIONID |
			TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | WRITE_DAC | WRITE_OWNER | DELETE |
			ACCESS_SYSTEM_SECURITY | READ_CONTROL);
		
		LPWX_SECURITY_DESCRIPTOR sd = 0x0;
		wx_status = SeAllocateAndInitializeSecurityDescriptor(0x0, SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT, account->integrity_level.level, account->sid, 0x0,
			dacl, 0x0, &sd);
		if (!WX_SUCCESS(wx_status) || IsBadPointer(sd)) goto FREE_DACL;
		else {
			LPOBJECT_HEADER object_hdr = 0x0;
			wx_status = ObCreateObject(OB_OBJECT_TYPE_ACCESS_TOKEN, 0x0, 0x0, sizeof _WX_ACCESS_TOKEN, sd, &object_hdr, 0x0);
			if (!WX_SUCCESS(wx_status) || IsBadPointer(object_hdr)) goto FREE_SD;
			else {
				LPWX_ACCESS_TOKEN access_token = (LPWX_ACCESS_TOKEN)(object_hdr + 1);

				access_token->type = token_type;

				EnterCriticalSection(&default_owner->lock);
				if (default_owner->attributes & SE_SID_USER) access_token->default_owner = default_owner;
				LeaveCriticalSection(&default_owner->lock);

				if (!IsBadPointer(default_group)) {
					EnterCriticalSection(&default_group->lock);
					if (default_group->attributes & SE_SID_GROUP) access_token->default_group = default_group;
					LeaveCriticalSection(&default_group->lock);
				}

				WxInitializeListHead(&access_token->group_list_head);
				WxInitializeListHead(&access_token->privilege_list_head);

				EnterCriticalSection(&account->lock);
				access_token->integrity_level = account->integrity_level;
				access_token->user = account->sid;
				
				LPWX_LIST_ENTRY group_iterator = account->group_list_head.Flink;
				while (group_iterator != &account->group_list_head) {
					LPWX_ACCOUNT group_account = CONTAINING_RECORD(group_iterator, WX_ACCOUNT, link);
					if(!IsBadPointer(group_account) && group_account->type == SE_ACCOUNT_TYPE_GROUP) {
						LPWX_SID sid = 0x0;
						if (WX_SUCCESS(SeDuplicateSid(group_account->sid, &sid)) && !IsBadPointer(sid)) WxInsertTailList(&access_token->group_list_head, &sid->link);
					}
					group_iterator = group_iterator->Flink;
				}

				LPWX_LIST_ENTRY privilege_iterator = account->privilege_list_head.Flink;
				while (privilege_iterator != &account->privilege_list_head) {
					LPWX_PRIVILEGE privilege = CONTAINING_RECORD(privilege_iterator, WX_PRIVILEGE, link);
					if (!IsBadPointer(privilege)) {
						LPWX_PRIVILEGE __privilege = 0x0;
						ULONG __create_disposition = 0x0;
						if (WX_SUCCESS(SeCreatePrivilege(privilege->name.Buffer, privilege->name.Length / 0x2, 0x0, &__privilege, &__create_disposition)) && 
							__create_disposition == SE_OPENED) WxInsertTailList(&access_token->privilege_list_head, &__privilege->link);
					}
					privilege_iterator = privilege_iterator->Flink;
				}

				LeaveCriticalSection(&account->lock);

				if (access_token->type == SE_IMPERSONATION_ACCESS_TOKEN) access_token->impersonation_level = impersonation_level;

				InitializeCriticalSection(&access_token->lock);
				WxInitializeListHead(&access_token->restricted_sid_list_head);

				if (!IsBadPointer(out_access_token)) *out_access_token = access_token;
				return WXSTATUS_SUCCESS;

			}
		FREE_SD:
			HeapFree(default_heap, 0x8, sd);
		}
	FREE_DACL:
		HeapFree(default_heap, 0x8, dacl);
	}

EPILOGUE:
	return wx_status;
}

WXSTATUS __stdcall SeAllocateAndIitializeAcl(ULONG acl_type, LPWX_ACCESS_CONTROL_LIST* out_acl) {
	if (acl_type != SE_ACL_TYPE_DISCRITIONARY && acl_type != SE_ACL_TYPE_SECURITY) return WXSTATUS_FAILED;

	LPWX_ACCESS_CONTROL_LIST acl = (LPWX_ACCESS_CONTROL_LIST)HeapAlloc(GetProcessHeap(), 0x8, sizeof _WX_ACCESS_CONTROL_LIST);
	if (IsBadPointer(acl)) return WXSTATUS_FAILED;

	acl->type = acl_type;
	
	InitializeCriticalSection(&acl->lock);

	WxInitializeListHead(&acl->allow_ace_list_head);
	WxInitializeListHead(&acl->deny_ace_list_head);
	WxInitializeListHead(&acl->failure_audit_ace_list_head);
	WxInitializeListHead(&acl->success_audit_ace_list_head);
	WxInitializeListHead(&acl->mix_audit_ace_list_head);

	if (!IsBadPointer(out_acl)) *out_acl = acl;

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeAddAceToAcl(LPWX_ACCESS_CONTROL_LIST target_acl, ULONG ace_type, LPWX_SID trustee, WX_ACCESS_MASK access_rights) {
	if (IsBadPointer(target_acl) || (ace_type != SE_ACE_TYPE_ALLOW && ace_type != SE_ACE_TYPE_DENY && ace_type != SE_ACE_TYPE_FAILURE_AUDIT &&
		ace_type != SE_ACE_TYPE_MIX_AUDIT && ace_type != SE_ACE_TYPE_SUCCESS_AUDIT) || IsBadPointer(trustee)) return WXSTATUS_FAILED;

	EnterCriticalSection(&target_acl->lock);

	WXSTATUS wx_status = WXSTATUS_FAILED;
	LPWX_ACCESS_CONTROL_ENTRY ace = 0x0;
	WX_LIST_ENTRY* ace_list_head = 0x0;

	if ((target_acl->type == SE_ACL_TYPE_DISCRITIONARY && (ace_type == SE_ACE_TYPE_ALLOW || ace_type == SE_ACE_TYPE_DENY)) || 
		(target_acl->type == SE_ACL_TYPE_SECURITY && (ace_type == SE_ACE_TYPE_FAILURE_AUDIT || ace_type == SE_ACE_TYPE_SUCCESS_AUDIT || ace_type == SE_ACE_TYPE_MIX_AUDIT))) { 
		ace = (LPWX_ACCESS_CONTROL_ENTRY)HeapAlloc(GetProcessHeap(), 0x8, sizeof _WX_ACCESS_CONTROL_ENTRY);
		switch (ace_type) {
			case SE_ACE_TYPE_ALLOW: ace_list_head = &target_acl->allow_ace_list_head; break;
			case SE_ACE_TYPE_DENY: ace_list_head = &target_acl->deny_ace_list_head; break;
			case SE_ACE_TYPE_FAILURE_AUDIT: ace_list_head = &target_acl->failure_audit_ace_list_head; break;
			case SE_ACE_TYPE_SUCCESS_AUDIT: ace_list_head = &target_acl->success_audit_ace_list_head; break;
			case SE_ACE_TYPE_MIX_AUDIT: ace_list_head = &target_acl->mix_audit_ace_list_head; break;
		}
	}

	if (IsBadPointer(ace) || IsBadPointer(ace_list_head)) goto UNLOCK_ACL;
	else {
		ace->type = ace_type;
		ace->trustee = trustee;
		ace->access_rights = access_rights;

		InitializeCriticalSection(&ace->lock);

		WxInsertTailList(ace_list_head, &ace->link);
	}

UNLOCK_ACL:
	LeaveCriticalSection(&target_acl->lock);
	return wx_status;
}

WXSTATUS __stdcall SeGetAceAt(LPWX_ACCESS_CONTROL_LIST acl, LONG ace_index, ULONG ace_type, LPWX_ACCESS_CONTROL_ENTRY* out_ace) {
	if(IsBadPointer(acl) || ace_index < 0x0) return WXSTATUS_FAILED;

	EnterCriticalSection(&acl->lock);

	WXSTATUS wx_status = WXSTATUS_FAILED;
	WX_LIST_ENTRY* ace_list_head = 0x0;

	if ((acl->type == SE_ACL_TYPE_DISCRITIONARY && (ace_type == SE_ACE_TYPE_ALLOW || ace_type == SE_ACE_TYPE_DENY)) ||
		(acl->type == SE_ACL_TYPE_SECURITY && (ace_type == SE_ACE_TYPE_FAILURE_AUDIT || ace_type == SE_ACE_TYPE_SUCCESS_AUDIT || ace_type == SE_ACE_TYPE_MIX_AUDIT))) {
		switch (ace_type) {
			case SE_ACE_TYPE_ALLOW: ace_list_head = &acl->allow_ace_list_head; break;
			case SE_ACE_TYPE_DENY: ace_list_head = &acl->deny_ace_list_head; break;
			case SE_ACE_TYPE_FAILURE_AUDIT: ace_list_head = &acl->failure_audit_ace_list_head; break;
			case SE_ACE_TYPE_SUCCESS_AUDIT: ace_list_head = &acl->success_audit_ace_list_head; break;
			case SE_ACE_TYPE_MIX_AUDIT: ace_list_head = &acl->mix_audit_ace_list_head; break;
		}
	}

	if (IsBadPointer(ace_list_head)) goto UNLOCK_ACL;
	else {
		WX_LIST_ENTRY* ace_iterator = 0x0;
		UINT i = 0x0;
		while (ace_iterator != ace_list_head && i < ace_index) {
			i++;
			ace_iterator = ace_iterator->Flink;
		}

		if (ace_iterator == ace_list_head) goto UNLOCK_ACL;
		else {
			wx_status = WXSTATUS_SUCCESS;
			if (!IsBadPointer(out_ace)) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) *out_ace = ace;
			}
		}
	}

UNLOCK_ACL:
	LeaveCriticalSection(&acl->lock);
	return wx_status;
}

WXSTATUS __stdcall SeRemoveAceFromAcl(LPWX_ACCESS_CONTROL_LIST acl, LONG ace_index, ULONG ace_type, LPWX_ACCESS_CONTROL_ENTRY* out_ace) {
	LPWX_ACCESS_CONTROL_ENTRY ace = 0x0;
	WXSTATUS wx_status = SeGetAceAt(acl, ace_index, ace_type, &ace);
	if (!WX_SUCCESS(wx_status) || !IsBadPointer(ace)) return WXSTATUS_FAILED;

	EnterCriticalSection(&acl->lock);
	WxRemoveFromList(&ace->link);
	LeaveCriticalSection(&acl->lock);

	if (!IsBadPointer(out_ace)) *out_ace = ace;
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeAllocateAndInitializeSecurityDescriptor(LPWX_ACCESS_TOKEN creator_access_token, WORD format, ULONG integrity_level, LPWX_SID owner, LPWX_SID group, LPWX_ACCESS_CONTROL_LIST dacl, LPWX_ACCESS_CONTROL_LIST sacl, LPWX_SECURITY_DESCRIPTOR* out_sd) {
	if (format != SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT && format != SE_SECURITY_DESCRIPTOR_SELF_RELATIVE_FROMAT) return WXSTATUS_FAILED;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	LPWX_SECURITY_DESCRIPTOR sd = (LPWX_SECURITY_DESCRIPTOR)HeapAlloc(default_heap, 0x8, sizeof _WX_SECURITY_DESCRIPTOR);
	if (IsBadPointer(sd)) return WXSTATUS_FAILED;

	ULONG __integrity_level = 0x0;
	LPWX_SID __owner = 0x0, __group = 0x0;

	if (owner) __owner = owner;
	if (group) __group = group;
	if (integrity_level != 0xFFFFFFFF) __integrity_level = integrity_level;
	if (!IsBadPointer(creator_access_token)) {
		EnterCriticalSection(&creator_access_token->lock);
		if (!__integrity_level) __integrity_level = creator_access_token->integrity_level.level;
		if (!__owner) __owner = creator_access_token->default_owner;
		if (!__group) __group = creator_access_token->default_group;
		LeaveCriticalSection(&creator_access_token->lock);
	}

	InitializeCriticalSection(&sd->lock);

	WXSTATUS wx_status = WXSTATUS_SUCCESS;

	sd->format = format;
	sd->integrity_level.level = __integrity_level;
	if (sd->format == SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT) {
		sd->owner = __owner;
		sd->group = __group;
		if (sd->owner) sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_OWNER_PRESENT;
		if(sd->group) sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_GROUP_PRESENT;
	}
	else if (sd->format == SE_SECURITY_DESCRIPTOR_SELF_RELATIVE_FROMAT) {
		if (__owner) {
			EnterCriticalSection(&__owner->lock);
			sd->_owner.attributes = __owner->attributes;
			sd->_owner.auth = __owner->auth;
			sd->_owner.id = __owner->id;
			sd->_owner.link = __owner->link;
			LeaveCriticalSection(&__owner->lock);
			InitializeCriticalSection(&sd->_owner.lock);
			sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_OWNER_PRESENT;
		}
		if (__group) {
			EnterCriticalSection(&__group->lock);
			sd->_group.attributes = __group->attributes;
			sd->_group.auth = __group->auth;
			sd->_group.id = __group->id;
			sd->_group.link = __group->link;
			LeaveCriticalSection(&__group->lock);
			InitializeCriticalSection(&sd->_group.lock);
			sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_GROUP_PRESENT;
		}
	}
	else wx_status = WXSTATUS_FAILED;

	if (!WX_SUCCESS(wx_status)) goto FREE_SECURITY_DESCRIPTOR;
	else {
		SeSetSecurityDescriptorAcl(sd, dacl, 0x0);
		SeSetSecurityDescriptorAcl(sd, sacl, 0x0);
		goto EPILOGUE;
	}

FREE_SECURITY_DESCRIPTOR:
	HeapFree(default_heap, 0x8, sd);
EPILOGUE:
	if (WX_SUCCESS(wx_status) && !IsBadPointer(out_sd)) *out_sd = sd;
	return wx_status;
}

WXSTATUS __stdcall SeDuplicateAcl(LPWX_ACCESS_CONTROL_LIST dest_acl, LPWX_ACCESS_CONTROL_LIST src_acl) {
	if (!IsBadPointer(dest_acl) && !IsBadPointer(src_acl) && (src_acl->type == SE_ACL_TYPE_DISCRITIONARY || src_acl->type == SE_ACL_TYPE_SECURITY)) {
		dest_acl->type = src_acl->type;
		InitializeCriticalSection(&dest_acl->lock);
		if (dest_acl->type == SE_ACL_TYPE_DISCRITIONARY) {
			WxInitializeListHead(&dest_acl->allow_ace_list_head);
			WxInitializeListHead(&dest_acl->deny_ace_list_head);

			WX_LIST_ENTRY* ace_iterator = src_acl->allow_ace_list_head.Flink;
			while (ace_iterator != &src_acl->allow_ace_list_head) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) SeAddAceToAcl(dest_acl, SE_ACE_TYPE_ALLOW, ace->trustee, ace->access_rights);
				ace_iterator = ace_iterator->Flink;
			}
			ace_iterator = src_acl->deny_ace_list_head.Flink;
			while (ace_iterator != &src_acl->deny_ace_list_head) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) SeAddAceToAcl(dest_acl, SE_ACE_TYPE_DENY, ace->trustee, ace->access_rights);
				ace_iterator = ace_iterator->Flink;
			}
		}
		else if (dest_acl->type == SE_ACL_TYPE_SECURITY) {
			WxInitializeListHead(&dest_acl->failure_audit_ace_list_head);
			WxInitializeListHead(&dest_acl->success_audit_ace_list_head);
			WxInitializeListHead(&dest_acl->mix_audit_ace_list_head);

			WX_LIST_ENTRY* ace_iterator = src_acl->failure_audit_ace_list_head.Flink;
			while (ace_iterator != &src_acl->failure_audit_ace_list_head) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) SeAddAceToAcl(dest_acl, SE_ACE_TYPE_FAILURE_AUDIT, ace->trustee, ace->access_rights);
				ace_iterator = ace_iterator->Flink;
			}
			ace_iterator = src_acl->success_audit_ace_list_head.Flink;
			while (ace_iterator != &src_acl->success_audit_ace_list_head) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) SeAddAceToAcl(dest_acl, SE_ACE_TYPE_SUCCESS_AUDIT, ace->trustee, ace->access_rights);
				ace_iterator = ace_iterator->Flink;
			}
			ace_iterator = src_acl->mix_audit_ace_list_head.Flink;
			while (ace_iterator != &src_acl->mix_audit_ace_list_head) {
				LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
				if (!IsBadPointer(ace)) SeAddAceToAcl(dest_acl, SE_ACE_TYPE_MIX_AUDIT, ace->trustee, ace->access_rights);
				ace_iterator = ace_iterator->Flink;
			}
		}
		return WXSTATUS_SUCCESS;
	}
	return WXSTATUS_FAILED;
}

WXSTATUS __stdcall SeSetSecurityDescriptorAcl(PWX_SECURITY_DESCRIPTOR sd, LPWX_ACCESS_CONTROL_LIST acl, LPWX_ACCESS_CONTROL_LIST old_acl) {
	if (IsBadPointer(sd) || IsBadPointer(acl) || acl->type > 0x1) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_SUCCESS;
	

	EnterCriticalSection(&sd->lock);

	if (sd->format == SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT) {
		if (!IsBadPointer(old_acl)) SeDuplicateAcl(old_acl, sd->acls[acl->type]);
		sd->acls[acl->type] = acl;
	}
	else if (sd->format == SE_SECURITY_DESCRIPTOR_SELF_RELATIVE_FROMAT) {
		if (!IsBadPointer(old_acl)) SeDuplicateAcl(old_acl, &sd->_acls[acl->type]);
		wx_status = SeDuplicateAcl(&sd->_acls[acl->type], acl);
	}
	else wx_status = WXSTATUS_FAILED;

	LeaveCriticalSection(&sd->lock);

	if (WX_SUCCESS(wx_status)) {
		if (acl->type == SE_ACL_TYPE_DISCRITIONARY) sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT;
		else sd->flags |= SE_SECURITY_DESCRIPTOR_FLAG_SACL_PRESENT;
	}

	return wx_status;
}

WXSTATUS __stdcall SeLookupAccountBySid(LPWX_SID sid, LPWX_ACCOUNT* out_account) {
	if (IsBadPointer(sid)) return WXSTATUS_FAILED;

	EnterCriticalSection(&srm_manager.sam_database->lock);

	WX_LIST_ENTRY* account_iterator = srm_manager.sam_database->account_list_head.Flink;
	WX_LIST_ENTRY* account_list_head = &srm_manager.sam_database->account_list_head;

	LPWX_ACCOUNT account = 0x0;

	while (account_iterator != account_list_head) {
		account = CONTAINING_RECORD(account_iterator, WX_ACCOUNT, link);
		if (!IsBadPointer(account) && SeCompareLuid(account->sid->id, sid->id)) break;
		account_iterator = account_iterator->Flink;
	}

	LeaveCriticalSection(&srm_manager.sam_database->lock);

	if (account_iterator == account_list_head || IsBadPointer(account)) return WXSTATUS_NOT_FOUND;

	if (!IsBadPointer(out_account)) *out_account = account;
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeCreateRestrictedAccessToken(PWX_ACCESS_TOKEN src_access_token, LPWX_SID* restricted_sids, ULONG restricted_sids_count, LPWX_ACCESS_TOKEN* out_access_token) {
	if (IsBadPointer(src_access_token) || IsBadPointer(restricted_sids) || !restricted_sids_count) return WXSTATUS_FAILED;

	LPWX_ACCOUNT account = 0x0;
	WXSTATUS wx_status = SeLookupAccountBySid(src_access_token->user, &account);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(account)) return WXSTATUS_FAILED;

	LPWX_ACCESS_TOKEN access_token = 0x0;
	wx_status = SeAllocateAndInitializeAccessToken(account, src_access_token->type, src_access_token->impersonation_level, src_access_token->default_owner,
		src_access_token->default_group, &access_token);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(access_token)) return WXSTATUS_FAILED;

	for (UINT i = 0x0; i < restricted_sids_count; i++) {
		if (!IsBadPointer(restricted_sids[i])) {
			EnterCriticalSection(&restricted_sids[i]->lock);
			WxInsertTailList(&access_token->restricted_sid_list_head, &restricted_sids[i]->link);
			LeaveCriticalSection(&restricted_sids[i]->lock);
		}
	}

	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeAccessCheck(PWX_ACCESS_TOKEN access_token, LPVOID object, WX_ACCESS_MASK access_rights, WX_ACCESS_MASK* granted_access_rights) {
	if (IsBadPointer(access_token) || IsBadPointer(object)) return WXSTATUS_FAILED;

	LPOBJECT_HEADER object_hdr = ObGetObjectHeader(object);
	if(IsBadPointer(object_hdr)) return WXSTATUS_FAILED;

	EnterCriticalSection(&object_hdr->lock);
	LPOBJECT_TYPE object_type = object_hdr->object_type;
	LeaveCriticalSection(&object_hdr->lock);
	if (IsBadPointer(object_type)) return WXSTATUS_FAILED;

	EnterCriticalSection(&object_hdr->lock);
	LPWX_SECURITY_DESCRIPTOR sd = object_hdr->security_descriptor;
	LeaveCriticalSection(&object_hdr->lock);
	if(IsBadPointer(sd)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_ACCESS_CHECK_SUCCEEDED;

	EnterCriticalSection(&access_token->lock);
	EnterCriticalSection(&sd->lock);
	if (access_token->integrity_level.level < sd->integrity_level.level && !(sd->integrity_level.level & SE_WRITE_ALLOWED_FOR_LOWER_INTEGRITY_LEVELS))
		wx_status = WXSTATUS_ACCESS_CHECK_FAILED;
	LeaveCriticalSection(&sd->lock);
	LeaveCriticalSection(&access_token->lock);

	if (wx_status == WXSTATUS_ACCESS_CHECK_FAILED) return wx_status;

	EnterCriticalSection(&sd->lock);
	LPWX_ACCESS_CONTROL_LIST dacl = sd->format == SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT ? sd->acls[0x0] : &sd->_acls[0x0];
	LeaveCriticalSection(&sd->lock);
	if (!dacl) return WXSTATUS_ACCESS_CHECK_SUCCEEDED;

	if (IsBadPointer(dacl) || dacl->type != SE_ACL_TYPE_DISCRITIONARY) return WXSTATUS_FAILED;

	WX_ACCESS_MASK mapped_access_rights = access_rights;
	if (access_rights != MAXIMUM_ALLOWED) {
		wx_status = object_type->ObGenericAccessRightsMapper(object_type, access_rights, &mapped_access_rights);
		if (!WX_SUCCESS(wx_status) || mapped_access_rights == WX_INVALID_ACCESS_RIGHT) return WXSTATUS_FAILED;
		EnterCriticalSection(&object_type->lock);
		if ((object_type->valid_acess_rights_mask & mapped_access_rights) != mapped_access_rights) wx_status = WXSTATUS_ACCESS_CHECK_FAILED;
		LeaveCriticalSection(&object_type->lock);
		if (!WX_SUCCESS(wx_status)) return WXSTATUS_ACCESS_CHECK_FAILED;
	}

	EnterCriticalSection(&access_token->lock);
	EnterCriticalSection(&dacl->lock);

	WX_ACCESS_MASK allowed_access_mask = 0x0, denied_access_mask = 0x0;

	wx_status = WXSTATUS_ACCESS_CHECK_SUCCEEDED;

	LPWX_LIST_ENTRY ace_iterator = dacl->deny_ace_list_head.Flink;
	LPWX_LIST_ENTRY deny_ace_list_head = &dacl->deny_ace_list_head;
	while (ace_iterator != deny_ace_list_head) {
		LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
		if (!IsBadPointer(ace) && ace->type == SE_ACE_TYPE_DENY && WX_SUCCESS(SeIsAceAppliable(access_token, ace, 0x0))) {
			EnterCriticalSection(&ace->lock);
			WX_ACCESS_MASK ace_access_rights = ace->access_rights;
			LeaveCriticalSection(&ace->lock);
			if (access_rights != MAXIMUM_ALLOWED) {
				if ((ace_access_rights & mapped_access_rights)) {
					wx_status = WXSTATUS_ACCESS_CHECK_FAILED;
					break;
				}
			}
			else denied_access_mask |= ace_access_rights;
		}
		ace_iterator = ace_iterator->Flink;
	}
	if (!WX_SUCCESS(wx_status)) goto EPILOGUE;
	else {
		wx_status = WXSTATUS_ACCESS_CHECK_FAILED;

		ace_iterator = dacl->allow_ace_list_head.Flink;
		LPWX_LIST_ENTRY allow_ace_list_head = &dacl->allow_ace_list_head;
		while (ace_iterator != allow_ace_list_head) {
			LPWX_ACCESS_CONTROL_ENTRY ace = CONTAINING_RECORD(ace_iterator, WX_ACCESS_CONTROL_ENTRY, link);
			LPWX_SID sid = 0x0;
			if (!IsBadPointer(ace) && ace->type == SE_ACE_TYPE_ALLOW && WX_SUCCESS(SeIsAceAppliable(access_token, ace, &sid)) && !(sid->attributes & SE_SID_DENY_ONLY)) {
				EnterCriticalSection(&ace->lock);
				WX_ACCESS_MASK ace_access_mask = ace->access_rights;
				if (access_rights != MAXIMUM_ALLOWED) {
					if (ace_access_mask & mapped_access_rights) mapped_access_rights &= ~ace_access_mask;
				}
				else allowed_access_mask |= ace_access_mask;
			}
			ace_iterator = ace_iterator->Flink;
		}

		if (access_rights != MAXIMUM_ALLOWED) wx_status = mapped_access_rights ? WXSTATUS_ACCESS_CHECK_FAILED : WXSTATUS_ACCESS_CHECK_SUCCEEDED;
		else {
			allowed_access_mask &= ~denied_access_mask;
			wx_status = WXSTATUS_ACCESS_CHECK_SUCCEEDED;
		}
	}

EPILOGUE:
	LeaveCriticalSection(&dacl->lock);
	LeaveCriticalSection(&access_token->lock);
	if (WX_SUCCESS(wx_status) && !IsBadPointer(granted_access_rights)) {
		if (access_rights == MAXIMUM_ALLOWED) *granted_access_rights = allowed_access_mask;
		else *granted_access_rights = access_rights;
	}
	return wx_status;
}

WXSTATUS __stdcall SePrivilegeCheck(PWX_ACCESS_TOKEN access_token, LPWX_PRIVILEGE* privileges, ULONG privileges_count) {
	if (IsBadPointer(access_token) || IsBadPointer(privileges) || !privileges_count) return WXSTATUS_FAILED;

	EnterCriticalSection(&access_token->lock);

	ULONG enabled_privileged = 0x0;

	for (UINT i = 0x0; i < privileges_count; i++) {
		if (!IsBadPointer(privileges[i])) {
			EnterCriticalSection(&privileges[i]->lock);
			
			LPWX_LIST_ENTRY privilege_iterator = access_token->privilege_list_head.Flink;
			while (privilege_iterator != &access_token->privilege_list_head) {
				LPWX_PRIVILEGE __privilege = CONTAINING_RECORD(privilege_iterator, WX_PRIVILEGE, link);
				if (!IsBadPointer(__privilege)) {
					EnterCriticalSection(&__privilege->lock);
					if((__privilege->attributes & SE_PRIVILEGE_ENABLED) && SeCompareLuid(__privilege->id, privileges[i]->id)) enabled_privileged++;
					LeaveCriticalSection(&__privilege->lock);
				}
				privilege_iterator = privilege_iterator->Flink;
			}

			LeaveCriticalSection(&privileges[i]->lock);
		}
	}
	LeaveCriticalSection(&access_token->lock);

	return enabled_privileged == privileges_count ? WXSTATUS_ACCESS_CHECK_SUCCEEDED : WXSTATUS_ACCESS_CHECK_FAILED;
}

WXSTATUS __stdcall SeIsAceAppliable(LPWX_ACCESS_TOKEN access_token, LPWX_ACCESS_CONTROL_ENTRY ace, LPWX_SID* out_sid) {
	if (IsBadPointer(access_token) || IsBadPointer(ace)) return WXSTATUS_FAILED;

	WXSTATUS wx_status = WXSTATUS_FAILED;

	EnterCriticalSection(&access_token->lock);
	EnterCriticalSection(&ace->lock);

	if (SeCompareLuid(access_token->user->id, ace->trustee->id)) {
		wx_status = WXSTATUS_SUCCESS;
		if (!IsBadPointer(out_sid)) *out_sid = access_token->user;
	}
	else {
		LPWX_LIST_ENTRY group_iterator = access_token->group_list_head.Flink;
		LPWX_LIST_ENTRY group_list_head = &access_token->group_list_head;
		while (group_iterator != group_list_head) {
			LPWX_SID group_sid = CONTAINING_RECORD(group_iterator, WX_SID, link);
			if (!IsBadPointer(group_sid) && (group_sid->attributes & SE_SID_GROUP) && SeCompareLuid(group_sid->id, ace->trustee->id)) {
				wx_status = WXSTATUS_SUCCESS;
				if (!IsBadPointer(out_sid)) *out_sid = group_sid;
				goto EPILOGUE;
			}
			group_iterator = group_iterator->Flink;
		}

		if (access_token->restricted_sid_list_head.Flink != &access_token->restricted_sid_list_head &&
			access_token->restricted_sid_list_head.Blink != &access_token->restricted_sid_list_head) {
			LPWX_LIST_ENTRY restricted_sid_iterator = access_token->restricted_sid_list_head.Flink;
			LPWX_LIST_ENTRY restricted_sid_list_head = &access_token->restricted_sid_list_head;
			while (restricted_sid_iterator != restricted_sid_list_head) {
				LPWX_SID restricted_sid = CONTAINING_RECORD(restricted_sid_iterator, WX_SID, link);
				if (!IsBadPointer(restricted_sid) && SeCompareLuid(restricted_sid->id, ace->trustee->id)) {
					wx_status = WXSTATUS_SUCCESS;
					if (!IsBadPointer(out_sid)) *out_sid = restricted_sid;
					goto EPILOGUE;
				}
				group_iterator = group_iterator->Flink;
			}
		}
	}

EPILOGUE:
	LeaveCriticalSection(&ace->lock);
	LeaveCriticalSection(&access_token->lock);
	return wx_status;
}

BOOLEAN __stdcall SeCompareLuid(WX_LUID luid_0, WX_LUID luid_1) {
	return luid_0.low_part == luid_1.low_part && luid_0.high_part == luid_1.high_part;
}

BOOLEAN __stdcall SeIsValidAccountName(LPCWSTR account_name, ULONG name_len) {
	if (!account_name || !name_len) return 0x0;
	BOOLEAN b_valid = 0x1;
	for (UINT i = 0x0; i < name_len; i++) if (account_name[i] == L'\\' || account_name[i] == L'/') {
		b_valid = 0x0;
		break;
	}
	return b_valid;
}

WXSTATUS __stdcall SeSelfRelativeToAbsoluteSd(LPWX_SECURITY_DESCRIPTOR sd) {
	if(IsBadPointer(sd)) return WXSTATUS_FAILED;
	
	if (sd->format == SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT) return WXSTATUS_SUCCESS;

	HANDLE default_heap = GetProcessHeap();
	if (IsBadPointer(default_heap)) return WXSTATUS_FAILED;

	LPWX_SID owner = (LPWX_SID)HeapAlloc(default_heap, 0x8, sizeof _WX_SID);
	if (IsBadPointer(owner)) return WXSTATUS_FAILED;

	LPWX_SID group = (LPWX_SID)HeapAlloc(default_heap, 0x8, sizeof _WX_SID);
	if (IsBadPointer(group)) goto FREE_OWNER;
	else {
		LPWX_ACCESS_CONTROL_LIST dacl = 0x0;
		WXSTATUS wx_status = SeAllocateAndIitializeAcl(SE_ACL_TYPE_DISCRITIONARY, &dacl);
		if (!WX_SUCCESS(wx_status) || IsBadPointer(dacl)) goto FREE_GROUP;
		else {
			LPWX_ACCESS_CONTROL_LIST sacl = 0x0;
			WXSTATUS wx_status = SeAllocateAndIitializeAcl(SE_ACL_TYPE_SECURITY, &sacl);
			if (!WX_SUCCESS(wx_status) || IsBadPointer(dacl)) goto FREE_DACL;
			else {
				EnterCriticalSection(&sd->lock);

				if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_OWNER_PRESENT) {
					owner->attributes = sd->_owner.attributes;
					owner->auth = sd->_owner.auth;
					owner->id = sd->_owner.id;
					owner->link = sd->_owner.link;
					InitializeCriticalSection(&owner->lock);
				}
				else {
					HeapFree(default_heap, 0x8, owner);
					owner = 0x0;
				}

				if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_GROUP_PRESENT) {
					group->attributes = sd->_group.attributes;
					group->auth = sd->_group.auth;
					group->id = sd->_group.id;
					group->link = sd->_group.link;
					InitializeCriticalSection(&group->lock);
				}
				else {
					HeapFree(default_heap, 0x8, group);
					group = 0x0;
				}

				if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT) wx_status = SeDuplicateAcl(dacl, &sd->_acls[0x0]);
				else {
					HeapFree(default_heap, 0x8, dacl);
					dacl = 0x0;
				}
				if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_SACL_PRESENT) wx_status = SeDuplicateAcl(sacl, &sd->_acls[0x1]);
				else {
					HeapFree(default_heap, 0x8, sacl);
					sacl = 0x0;
				}

				if (!WX_SUCCESS(wx_status)) goto UNLOCK_SECURITY_DESCRIPTOR;
				else {
					sd->owner = owner;
					sd->group = group;
					sd->acls[0x0] = dacl;
					sd->acls[0x1] = sacl;

					sd->format = SE_SECURITY_DESCRIPTOR_ABSOLUTE_FROMAT;
				}

			UNLOCK_SECURITY_DESCRIPTOR:
				LeaveCriticalSection(&sd->lock);
				if (WX_SUCCESS(wx_status)) return WXSTATUS_SUCCESS;
			FREE_SACL:
				HeapFree(default_heap, 0x8, sacl);
			}
			FREE_DACL:
				HeapFree(default_heap, 0x8, dacl);
		}
	}
FREE_GROUP:
	HeapFree(default_heap, 0x8, group);
FREE_OWNER:
	HeapFree(default_heap, 0x8, owner);
	return WXSTATUS_FAILED;
}

WXSTATUS __stdcall SeAbsoluteToSelfRelativeSd(LPWX_SECURITY_DESCRIPTOR sd) {
	if (IsBadPointer(sd)) return WXSTATUS_FAILED;
	
	if (sd->format == SE_SECURITY_DESCRIPTOR_SELF_RELATIVE_FROMAT) return WXSTATUS_SUCCESS;

	WXSTATUS wx_status = WXSTATUS_FAILED;

	EnterCriticalSection(&sd->lock);
	LPWX_SID owner = sd->owner, group = sd->group;
	LPWX_ACCESS_CONTROL_LIST dacl = sd->acls[0x0], sacl = sd->acls[0x1];

	sd->format = SE_SECURITY_DESCRIPTOR_SELF_RELATIVE_FROMAT;

	if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_OWNER_PRESENT && !IsBadPointer(owner)) {
		sd->_owner.attributes = owner->attributes;
		sd->_owner.auth = owner->auth;
		sd->_owner.id = owner->id;
		sd->_owner.link = owner->link;
		InitializeCriticalSection(&sd->_owner.lock);
	}

	if (sd->flags & SE_SECURITY_DESCRIPTOR_FLAG_GROUP_PRESENT && !IsBadPointer(group)) {
		sd->_group.attributes = group->attributes;
		sd->_group.auth = group->auth;
		sd->_group.id = group->id;
		sd->_group.link = group->link;
		InitializeCriticalSection(&sd->_group.lock);
	}

	wx_status = SeDuplicateAcl(&sd->_acls[0x0], dacl);
	wx_status = SeDuplicateAcl(&sd->_acls[0x1], sacl);

	LeaveCriticalSection(&sd->lock);
	return wx_status;
}

WXSTATUS __stdcall SeLogonUser(LPCWSTR name, ULONG cch_name, LPBYTE pwd_hash, ULONG pwd_hash_size, LPWX_ACCESS_TOKEN* out_access_token) {
	if (!name || !cch_name) return WXSTATUS_FAILED;

	LPWX_ACCOUNT account = 0x0;
	WXSTATUS wx_status = SeLookupAccountByName(name, cch_name, &account);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(account)) return WXSTATUS_NOT_FOUND;

	if(account->pwd && account->pwd->size && (account->pwd->size != (pwd_hash_size + sizeof _HASHED_PASSWORD) ||
		!cmp(pwd_hash, (LPBYTE)account->pwd + sizeof _HASHED_PASSWORD, pwd_hash_size))) return WXSTATUS_NOT_FOUND;

	LPWX_ACCESS_TOKEN access_token = 0x0;
	wx_status = SeAllocateAndInitializeAccessToken(account, SE_PRIMARY_ACCESS_TOKEN, 0x0, account->sid, 0x0, &access_token);
	if (!WX_SUCCESS(wx_status) || IsBadPointer(access_token)) return WXSTATUS_FAILED;

	if (!IsBadPointer(out_access_token)) *out_access_token = access_token;
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeLookupAccountByName(LPCWSTR name, ULONG cch_name, LPWX_ACCOUNT* out_account) {
	if (!name || !cch_name) return WXSTATUS_FAILED;

	EnterCriticalSection(&srm_manager.sam_database->lock);

	WX_LIST_ENTRY* account_iterator = srm_manager.sam_database->account_list_head.Flink;
	WX_LIST_ENTRY* account_list_head = &srm_manager.sam_database->account_list_head;

	LPWX_ACCOUNT account = 0x0;

	while (account_iterator != account_list_head) {
		account = CONTAINING_RECORD(account_iterator, WX_ACCOUNT, link);
		if (!IsBadPointer(account) && account->name.Length == (cch_name * 0x2) && cmp((LPBYTE)account->name.Buffer, (LPBYTE)name, account->name.Length)) break;
		account_iterator = account_iterator->Flink;
	}

	LeaveCriticalSection(&srm_manager.sam_database->lock);

	if (account_iterator == account_list_head || IsBadPointer(account)) return WXSTATUS_NOT_FOUND;

	if (!IsBadPointer(out_account)) *out_account = account;
	return WXSTATUS_SUCCESS;
}

WXSTATUS __stdcall SeAccessTokenMapGenericAccessRights(LPOBJECT_HEADER object_hdr, WX_ACCESS_MASK generic_access_rights, WX_ACCESS_MASK* specific_rights) {
	if (!IsBadPointer(object_hdr) && !IsBadPointer(specific_rights) && generic_access_rights) {
		*specific_rights = (generic_access_rights & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL));
		if ((generic_access_rights & GENERIC_READ) == GENERIC_READ) (*specific_rights) |= (TOKEN_QUERY | TOKEN_QUERY_SOURCE | DELETE | ACCESS_SYSTEM_SECURITY | READ_CONTROL);
		if ((generic_access_rights & GENERIC_WRITE) == GENERIC_WRITE) (*specific_rights) |= (TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES |
			TOKEN_ADJUST_SESSIONID | WRITE_DAC | WRITE_OWNER);
		if ((generic_access_rights & GENERIC_EXECUTE) == GENERIC_EXECUTE) (*specific_rights) |= (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY);
		if ((generic_access_rights & GENERIC_ALL) == GENERIC_ALL) (*specific_rights) |= object_hdr->object_type->valid_acess_rights_mask;
		return WXSTATUS_SUCCESS;
	}
	return WXSTATUS_FAILED;
}

// ================================================================================