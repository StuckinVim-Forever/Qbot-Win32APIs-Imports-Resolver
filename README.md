# Qbot-Win32APIs-Imports-Resolver

An IDA python script to help resolve binary imports that are resolved during run time by Qbot stagers and most of its modules.

Before using the script you must identify the functions responsible for constructing the imports, 
then proceed to fix the function type declaration to 

```C
"_DWORD *__usercall resolve_win32_apis@<eax>(SIZE_T a1@<edx>, int a2@<ecx>, int string_index)"  
```

in order to get the correct function declaration.

<img src="img\declare_broken.png"
     alt="Markdown Monster icon"
     width= 400px
     height= auto
     style="float: center; margin-center: 10px;" />

<img src="img\declare_fixed.png"
     alt="Markdown Monster icon"
     width= 400px
     height= auto
     style="float: center; margin-center: 10px;" />




Every call to the "resolve_win_32_api" function is basically a call to resolve a DLL name and its imports, if you need help decrypting DLL names use  <a href="https://github.com/StuckinVim-Forever/Qbot-Strings-Decrypter" target="_blank">Qbot-Strings-Decrypter</a>

<img src="img\dll_names.png"
     alt="Markdown Monster icon"
     width= 400px
     height= auto
     style="float: center; margin-center: 10px;" />


Now you can extract from the function call the requierments for the script to lpocate and reolve the imports.
```C
 struct_global_pointer = resolve_win32_apis(size, encrytpted_data, lib_name_decryption_index);
```

After editing the main function of the script you need to point the script to the on disk location of the DLL binary it self to start creating the imports.

If successful IDA pro will create a structure of the resolved imports used by Qbot.

<img src="img\struct.png"
     alt="Markdown Monster icon"
     width= 400px
     height= auto
     style="float: center; margin-center: 10px;" />


Then finally you can see that the imports are resolved as a structure members. 


<img src="img\before_script.png"
     alt="Markdown Monster icon"
     width= 600px
     height= auto
     style="float: center; margin-center: 10px;" />

<img src="img\after_script.png"
     alt="Markdown Monster icon"
     width= 600px
     height= auto
     style="float: center; margin-center: 10px;" />



