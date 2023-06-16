#include "regctrl.h"

// Handle to the driver
int countRecords = 0;

HANDLE g_Driver;

VOID __cdecl wmain(
    _In_ ULONG argc,
    _In_reads_(argc) LPCWSTR argv[])
{
    BOOL Result;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    Result = UtilLoadDriver(DRIVER_NAME, DRIVER_NAME_WITH_EXT, WIN32_DEVICE_NAME, &g_Driver);
    if (Result != TRUE) {
        ErrorPrint("UtilLoadDriver failed, exiting...");
        exit(1);
    }
    printf("\nDriver is loaded ...\n\n"); 
    parse_file();
    loop();
    UtilUnloadDriver(g_Driver, NULL, DRIVER_NAME);
}