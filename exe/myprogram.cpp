#define _CRT_SECURE_NO_WARNINGS
#include "regctrl.h"
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <Windows.h>

struct configuration {
    enum type { KEY, PROCESS } type;
    int levelIntegrity;
    char name[255];
    wchar_t wName[255];
} pointerConfiguration[100];


std::string utf8_encode(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;

}


extern "C" void parse_file() {
    HKEY hkey;
    LONG result;
    wchar_t buf[1000];
    DWORD bufsz = 1000;

    result = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Test",
        0, KEY_READ, &hkey);
    if (result != ERROR_SUCCESS) {
        std::cout << "Failed open key" << std::endl;
        return;
    }

    result = RegGetValue(
        hkey, NULL, L"param",
        RRF_RT_REG_SZ, 0, buf, &bufsz);
    if (result != ERROR_SUCCESS) {
        std::cout << "Failed read value" << std::endl;
        return;
    }


    std::string data_xml = utf8_encode(buf);
    std::cout << data_xml << std::endl;
    std::stringstream ss;
    ss << data_xml;

    // std::string path = "C:\\Users\\skarhassmen\\Desktop\\project\\exe\\config.xml";
    boost::property_tree::ptree pt;
    read_xml(ss, pt);
    std::cout << "Reading file... " << std::endl;
    BOOST_FOREACH(boost::property_tree::ptree::value_type & child, pt.get_child("list")) {
    	struct configuration new_data; 
    	std::string type = child.second.get<std::string>("<xmlattr>.type");
    	if (!strcmp(type.c_str(), "process")) 
    		new_data.type = new_data.PROCESS;
        else if (!strcmp(type.c_str(), "key")) 
        	new_data.type = new_data.KEY;

        std::string name = child.second.get<std::string>("<xmlattr>.name");
        strcpy(new_data.name, name.c_str());
        
        mbstowcs(new_data.wName, name.c_str(), name.size());

        new_data.wName[name.size()] = L'\0';
        wprintf(L"%s", new_data.wName);

        new_data.levelIntegrity = child.second.get<int>("<xmlattr>.level");

    	pointerConfiguration[countRecords] = new_data; 
    	countRecords++;
    }
    std::cout << "Configuration file was read successfully: " << std::endl;
    DWORD BytesReturned;
    for(int i = 0; i < countRecords; i++) {
        int Result = DeviceIoControl(g_Driver,
            IOCTL_DATA,
            &pointerConfiguration[i],
            sizeof(struct configuration),
            NULL,
            0,
            &BytesReturned,
            NULL);
        std::cout << pointerConfiguration[i].name << " " << i << " packet was send. Status: " << Result << " Error: " << GetLastError() << std::endl;
    }

    std::cout << "\n" << std::endl;
}

void notification() {
    while (1) {
        BOOL Result = false;
        char n;

        std::cout << "1 - enable notification PsSetCreateThreadNotifyRoutine" << std::endl;
        std::cout << "2 - disable notification PsSetCreateThreadNotifyRoutine" << std::endl;
        std::cout << "3 - return main menu" << std::endl << "> ";
        std::cin >> n;

        switch (n) {
        case '1':
            Result = DeviceIoControl(g_Driver,
                IOCTL_ENABLE_NOTIFICATION,
                NULL,
                0,
                NULL,
                0,
                NULL,
                NULL);
            break;
        case '2':
            Result = DeviceIoControl(g_Driver,
                IOCTL_DISABLE_NOTIFICATION,
                NULL,
                0,
                NULL,
                0,
                NULL,
                NULL);
            break;
        case '3':
            return;
        default:
            printf("Error command!\n");
        }

        if (Result)
            std::cout << "Successfully!" << std::endl << std::endl;
        else
            std::cout << "Did not work out" << std::endl << std::endl;
    }
}


extern "C" void loop() {
    while (1) {
        char n;
        std::cout << "\nChoose command:" << std::endl;
        std::cout << "1 - menu notification PsSetCreateThreadNotifyRoutine\n";
        std::cout << "2 - unload driver\n" << "> ";
        std::cin >> n;
        switch (n) {
        case '1': notification();
            break;
        case '2': return;
        default: 
            printf("Error command!\n\n");
            continue;
        }
    }
}
