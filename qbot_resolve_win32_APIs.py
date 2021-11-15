import pefile
import idc
import idautils
from idaapi import *
import idaapi
import binascii

def get_win32Api_DLL_exports(target_dll_path):
   list_of_dll_exports = []  
   pe =  pefile.PE(target_dll_path)
   for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    list_of_dll_exports.append((exp.name))
   return list_of_dll_exports

def resolve_single_api(api_name, api_real_hash , encrypted_api_hash,):
    test_api_enc_hash = api_real_hash ^  0x218FE95B
    if ( (test_api_enc_hash) == int(encrypted_api_hash, 16)):
        print("[+] Found a win32 api import " , api_name ," encrypted as ---> ", (encrypted_api_hash) )
        return True

def fetch_encrypted_library_hashes(size, encrypted_api_hash_location ):
    encrypted_apis_hashes_list = []
    counter =  size
    while(counter):
     binary_encrypted_hash = idc.get_wide_dword(encrypted_api_hash_location)
     encrypted_apis_hashes_list.append(hex(binary_encrypted_hash))
     encrypted_api_hash_location +=4
     counter -=1        
    return encrypted_apis_hashes_list

def create_imports_structure(target_dll ,sucessful_apis_list ):
    struct_name =  target_dll + "_array"
    structID = idc.add_struc(-1, struct_name, 0)
    for win32_api in sucessful_apis_list:
        print("[+] Setting structure member --->", win32_api)
        try:
         idc.add_struc_member(structID, win32_api.decode("utf-8"), -1, FF_DWORD , -1, 4)
        except Exception as stcut_add_memeber_err:
            print("[-] Failed to add struct member due to error --->", stcut_add_memeber_err)
    return struct_name


      

def resolve_imports(lib_name ,target_DLL_path, strcut_address, encrypted_pointer_address, size):
   sucessful_apis = []
   dll_exports =  get_win32Api_DLL_exports(target_DLL_path)
   encrypted_hashes = fetch_encrypted_library_hashes(size, encrypted_pointer_address)
   for enc_hash in encrypted_hashes:
        for api_name in dll_exports:
         api_real_crc32_hash =  binascii.crc32(api_name)
         if(resolve_single_api(api_name ,api_real_crc32_hash, enc_hash)):
            sucessful_apis.append(api_name) 
        
        
   if (len(sucessful_apis) >= 1 ):
    structure_name = create_imports_structure(lib_name,sucessful_apis )
    idc.set_name(strcut_address, structure_name + "_ptr")
    idc.SetType(strcut_address, structure_name +  "*" )
        


if __name__ == "__main__":
     #example below 
     #resolve_imports ("kernel32",  "C:\windows\syswow64\kernel32.dll", 0x3BAE684, 0x3BABA20, 0x11C)
     resolve_imports ("change_this_to_api_name",  "change_this_to_dll_path",
                      "change_to_struct_address", "change_to_encrypted_data_address", "change_to_size")
