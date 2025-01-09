#pragma once
#ifndef EVILBYTECODE_GATE_H
#define EVILBYTECODE_GATE_H

#include <windows.h>
#include <string>
#include <vector>

// Define SystemCall structure
struct SystemCall {
    LPCSTR fnName;
    DWORD Ssn;
};

// Define the PE parser class
class Pe {
public:
    PVOID ImageBase;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
    IMAGE_FILE_HEADER FileHeader;

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
};

// Function prototypes
Pe ParsePeImage(LPCSTR imageName);
std::vector<SystemCall> GetSystemCalls();
void Evilbytecode_SSN_Resolver(const std::vector<std::string>& functionNames);

#endif // EVILBYTECODE_GATE_H
