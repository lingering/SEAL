#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL GaloisKeys_Create1(void** galois_keys);

SEALDLL HRESULT SEALCALL GaloisKeys_Create2(void* copy, void** galois_keys);

SEALDLL HRESULT SEALCALL GaloisKeys_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL GaloisKeys_Set(void* thisptr, void* assign);

SEALDLL HRESULT SEALCALL GaloisKeys_Size(void* thisptr, int* size);

SEALDLL HRESULT SEALCALL GaloisKeys_DBC(void* thisptr, int* dbc);

SEALDLL HRESULT SEALCALL GaloisKeys_SetDBC(void* thisptr, int dbc);

SEALDLL HRESULT SEALCALL GaloisKeys_GetKeyCount(void* thisptr, int* key_count);

SEALDLL HRESULT SEALCALL GaloisKeys_GetKeyList(void* thisptr, int index, int* count, void** ciphers);

SEALDLL HRESULT SEALCALL GaloisKeys_GetKey(void* thisptr, uint64_t galois_elt, int* count, void** ciphers);

SEALDLL HRESULT SEALCALL GaloisKeys_ClearDataAndReserve(void* thisptr, int size);

SEALDLL HRESULT SEALCALL GaloisKeys_AddKeyList(void* thisptr, int count, void** ciphers);

SEALDLL HRESULT SEALCALL GaloisKeys_HasKey(void* thisptr, uint64_t galois_elt, bool* has_key);

SEALDLL HRESULT SEALCALL GaloisKeys_GetParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL GaloisKeys_SetParmsId(void* thisptr, uint64_t* parms_id);