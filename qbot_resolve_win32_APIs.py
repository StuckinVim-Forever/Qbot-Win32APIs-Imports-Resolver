import idc
import idautils
from idaapi import *
import idaapi
import binascii

import pefile
import platform

import sys

orig_stdout = sys.stdout
f = open('/Users/stuckinvim/Desktop/log.txt', 'w')
sys.stdout = f


#DLL libraries must match arch

'''
  dword_3BAE684 = resolve_win32_api_array(0x11Cu, &unk_3BABA20, 0x7C3);// kernel32.dll
  dword_3BAE6BC = resolve_win32_api_array(0x28u, &unk_3BABB40, 0xB62);// ntdll.dll
  dword_3BAE694 = resolve_win32_api_array(0x48u, &unk_3BABB70, 0x47D);// user32.dll
  dword_3BAE6B4 = resolve_win32_api_array(0x18u, &unk_3BABBBC, 0x9E8);// netapi32.dll
  dword_3BAE68C = resolve_win32_api_array(0xCCu, &unk_3BABBD8, 0x20C);// advapi32.dll
  dword_3BAE690 = resolve_win32_api_array(0x2Cu, &unk_3BABCA8, 0x8B3);// shlwapi.dll
  dword_3BAE698 = resolve_win32_api_array(8u, &unk_3BABCD8, 0x70D);// shell32.dll
  result = resolve_win32_api_array(4u, &unk_3BABCE4, 0x96E);// userenv.dl



 dword_3BAE680 = resolve_win32_api_array(0x10u, &unk_3BAB9C8, 0x4E5);// wtsapi32.dll
 
 
   dword_3BAE6A0 = resolve_win32_api_array(8u, &unk_3BABD20, 0x61E);// crypt32.dll
   
   

'''

#kernel32.dll
kernel32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/kernel32.dll'
kernel32_struct_global_address   =  0x3BAE684
kernel32_encrypted_data_address = 0x3BABA20

#ndll.dll
ntdll_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/ntdll.dll'
ntdll_struct_global_address   =  0x3BAE6BC
ntdll_encrypted_data_address = 0x3BABB40


#user32.dll
user32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/user32.dll'
user32_struct_global_address   =  0x3BAE694  
user32_encrypted_data_address = 0x3BABB70


#netapi32.dll
netapi32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/netapi32.dll'
netapi32_struct_global_address   =  0x3BAE6B4 
netapi32_encrypted_data_address = 0x3BABBBC


#advapi32.dll
advapi32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/advapi32.dll'
advapi32_struct_global_address   =  0x3BAE68C  
advapi32_encrypted_data_address = 0x3BABBD8



#shlwapi.dll
shlwapi_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/shlwapi.dll'
shlwapi_struct_global_address   =  0x3BAE690  
shlwapi_encrypted_data_address = 0x3BABCA8



#shell32.dll
shell32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/shell32.dll'
shell32_struct_global_address   =  0x3BAE698   
shell32_encrypted_data_address = 0x3BABCD8


#ws2_32.dll
ws2_32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/ws2_32.dll'
ws2_32_struct_global_address   =  0x10028408    
ws2_32_encrypted_data_address = 0x10021EEC


#userenv.dl
userenv_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/userenv.dll'
userenv_struct_global_address   =  0x3BAE6B8     
userenv_encrypted_data_address = 0x3BABCE4

#wininet.dll
wininet_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/wininet.dll'
wininet_struct_global_address   =  0x3BAE6A4      
wininet_encrypted_data_address = 0x3BABE08


#urlmon.dll
urlmon_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/urlmon.dll'
urlmon_struct_global_address   =  0x3BAE6B0      
urlmon_encrypted_data_address = 0x3BABE60



#wstapi32.dll
wstapi32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/wtsapi32.dll'
wstapi32_struct_global_address   =  0x3BAE680      
wstapi32_encrypted_data_address = 0x3BAB9C8


#wstapi32.dll
crypt32_dll_path = '/Users/stuckinvim/Desktop/apsis-windowsbins/x86/crypt32.dll'
crypt32_struct_global_address   =  0x3BAE6A0      
crypt32_encrypted_data_address = 0x3BABD20


def decrypt_string(index, key, enc_data, arg1=0, arg_2=0):

    decyrpted_data = ""
    while True:
        
        key_byte = idc.get_wide_byte(key +index ) 
        enc_byte = idc.get_wide_byte(enc_data +(index % 0x5A))
        decrypted_byte =  key_byte ^ enc_byte
        decyrpted_data += chr(decrypted_byte)
        #patch_byte(enc_data +(index % 0x5A) , decrypted_byte)
        if decrypted_byte == 0:
            break
        index +=1

    print("decrypted data is ---> ", decyrpted_data)
    return str(decyrpted_data)

#https://stackoverflow.com/questions/19325402/getting-iat-and-eat-from-pe
def get_DLL_exports(target_dll):
  list_of_dll_exports = []  
  pe =  pefile.PE(target_dll)
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   list_of_dll_exports.append((exp.name))
  #print (list_of_dll_exports)
  return list_of_dll_exports
    
    

#https://stackoverflow.com/questions/47342250/python3-find-crc32-of-string

def resolve_single_api(api_real_hash , encrypted_api_hash):
    print("searching real API hash --->", hex(api_real_hash))
    #get the dword at the location 
    test_api_enc_hash = api_real_hash ^  0x218FE95B
    print("test encrypted crc32 hash is --->", hex(test_api_enc_hash))
    if ( (test_api_enc_hash) == int(encrypted_api_hash, 16)):
        print("success found an encrypted hash---> ", (encrypted_api_hash) )
        return True


      

def fetch_encrypted_library_hashes(size, encrypted_api_hash_location ):
    encrypted_apis_hashes_list = []
    #get the dword at the location
    counter =  size #>> 4
    while(counter):
     print("counter is -->", counter)
     binary_encrypted_hash = idc.get_wide_dword(encrypted_api_hash_location)
     print("fetched crc32 at location ---> ",hex(encrypted_api_hash_location) , " is ---> ", hex(binary_encrypted_hash))
     encrypted_apis_hashes_list.append(hex(binary_encrypted_hash))
     encrypted_api_hash_location +=4
     counter -=1
     
             
    print(encrypted_apis_hashes_list)
    return encrypted_apis_hashes_list
    
    
    
    
def create_imports_strucutre(target_dll ,sucessful_apis_list ):
    struct_name =  target_dll + "_array"
    structID = idc.add_struc(-1, struct_name, 0)
    for win32_api in sucessful_apis_list:
        print("setting strucutre member --->", win32_api)
        try:
         idc.add_struc_member(structID, win32_api.decode("utf-8"), -1, FF_DWORD , -1, 4)
        except Exception as stcut_add_memeber_err:
            print("failed to add stuct meber due to error --->", stcut_add_memeber_err)
    return struct_name


  
#win_32_apis_array = resolve_win32_api_array_0(size, encrypted_data, ModuleHandleA);
def resolve_win32_apis_strucut(size , index):
    sucessful_apis = []
    # hash the target dll
    # for every hash in the return array of the dll
    
    if ('kernel32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "kernel32_dll"
          target_dll = kernel32_dll_path
          strcut_global_address = kernel32_struct_global_address
          encrypted_api_data = kernel32_encrypted_data_address
    
    if ('ntdll.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "ntdll_dll"
          target_dll = ntdll_dll_path
          strcut_global_address = ntdll_struct_global_address
          encrypted_api_data = ntdll_encrypted_data_address
          
    if ('user32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "user32_dll"
          target_dll = user32_dll_path
          strcut_global_address = user32_struct_global_address
          encrypted_api_data = user32_encrypted_data_address      
    
    if ('netapi32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "netapi32_dll"
          target_dll = netapi32_dll_path
          strcut_global_address = netapi32_struct_global_address
          encrypted_api_data = netapi32_encrypted_data_address
    
    if ('advapi32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "advapi32_dll"
          target_dll = advapi32_dll_path
          strcut_global_address = advapi32_struct_global_address
          encrypted_api_data = advapi32_encrypted_data_address
    
    if ('shlwapi.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "shlwapi_dll"
          target_dll = shlwapi_dll_path
          strcut_global_address = shlwapi_struct_global_address
          encrypted_api_data = shlwapi_encrypted_data_address
    
    if ('shell32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "shell32_dll"
          target_dll = shell32_dll_path
          strcut_global_address = shell32_struct_global_address
          encrypted_api_data = shell32_encrypted_data_address
    
    if ('ws2_32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "ws2_32_dll"
          target_dll = ws2_32_dll_path
          strcut_global_address = ws2_32_struct_global_address
          encrypted_api_data = ws2_32_encrypted_data_address
    
    if ('userenv.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "userenv_dll"
          target_dll = userenv_dll_path
          strcut_global_address = userenv_struct_global_address
          encrypted_api_data = userenv_encrypted_data_address
     
    if ('wininet.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "wininet_dll"
          target_dll = wininet_dll_path
          strcut_global_address = wininet_struct_global_address
          encrypted_api_data = wininet_encrypted_data_address
    
     
    if ('urlmon.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "urlmon_dll"
          target_dll = urlmon_dll_path
          strcut_global_address = urlmon_struct_global_address
          encrypted_api_data = urlmon_encrypted_data_address
    
         
    if ('wtsapi32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "wstapi32_dll"
          target_dll = wstapi32_dll_path
          strcut_global_address = wstapi32_struct_global_address
          encrypted_api_data = wstapi32_encrypted_data_address
    
    if ('crypt32.dll' in decrypt_string(index, 0x3BAD5A8, 0x3BAE3F8) ):
          lib_name = "crypt32_dll"
          target_dll = crypt32_dll_path
          strcut_global_address = crypt32_struct_global_address
          encrypted_api_data = crypt32_encrypted_data_address
    
    
    library_exports = get_DLL_exports(target_dll)
    binary_encrypted_hashes = fetch_encrypted_library_hashes(size, encrypted_api_data)
   
    #target_api_index = encrypted_api_data - size
    for enc_hash in binary_encrypted_hashes:
     for api_string in library_exports:
        try:
         api_real_crc32_hash =  binascii.crc32(api_string)
         print("export real hash --->", hex(api_real_crc32_hash ))
         #get the binary at the address
         print("stating the process to hunt for binary encrypted api --->  ", enc_hash)
         if(resolve_single_api(api_real_crc32_hash, enc_hash)):
            sucessful_apis.append(api_string) 
        except Exception as resolve_win32_api_err:
            print("failed to process win32api due to error ---->", resolve_win32_api_err)
            pass    
    #once the apis are discoverd test the returnedlist if it contains any memebr
    if (len(sucessful_apis) >= 1 ):
        strucutre_name = create_imports_strucutre(lib_name,sucessful_apis )
        
        idc.set_name(strcut_global_address, strucutre_name + "_ptr")
        idc.SetType(strcut_global_address, strucutre_name +  "*" )
         
    #if the list contains memebers start creating the strucutre
    
    
    
    print(sucessful_apis)     


#resolve_win32_apis_strucut(encrypted imports size ,encrypted_library_name_location)

'''
_DWORD *result; // eax

  dword_3BAE684 = resolve_win32_api_array(0x11Cu, &unk_3BABA20, 0x7C3);// kernel32.dll
  dword_3BAE6BC = resolve_win32_api_array(0x28u, &unk_3BABB40, 0xB62);// ntdll.dll
  dword_3BAE694 = resolve_win32_api_array(0x48u, &unk_3BABB70, 0x47D);// user32.dll
  dword_3BAE6B4 = resolve_win32_api_array(0x18u, &unk_3BABBBC, 0x9E8);// netapi32.dll
  dword_3BAE68C = resolve_win32_api_array(0xCCu, &unk_3BABBD8, 0x20C);// advapi32.dll
  dword_3BAE690 = resolve_win32_api_array(0x2Cu, &unk_3BABCA8, 0x8B3);// shlwapi.dll
  dword_3BAE698 = resolve_win32_api_array(8u, &unk_3BABCD8, 0x70D);// shell32.dll
  result = resolve_win32_api_array(4u, &unk_3BABCE4, 0x96E);// userenv.dl
  dword_3BAE6B8 = result;


'''
#kernel.dll  
resolve_win32_apis_strucut(0x11C ,0x7C3)
##ntdll.dll  
resolve_win32_apis_strucut(0x28 ,0xB62)
##user32.dll
resolve_win32_apis_strucut(0x48 ,0x47D)
##netapi32.dll
resolve_win32_apis_strucut(0x18 ,0x9E8)
##advapi32.dll
resolve_win32_apis_strucut(0xCC ,0x20C)
##shlwapi.dll
resolve_win32_apis_strucut(0x2C ,0x8B3)
#
##shell32.dll
resolve_win32_apis_strucut(8 ,0x70D)
#
##ws2_32.dll
resolve_win32_apis_strucut(0xC ,0xB2E)
#
#
##userenv.dll
resolve_win32_apis_strucut(4 ,0x70D)

#wininet.dll
resolve_win32_apis_strucut(0x54 ,0x100)



#urlmon.dll
resolve_win32_apis_strucut(4 ,0xB43)




#wstapi32.dll
resolve_win32_apis_strucut(0x10 ,0x4E5)

#crypt32.dll
resolve_win32_apis_strucut(8 ,0x61E)
