#pragma once
#include "EvilbytecodeGate.h"
#include <iostream>
#include <unordered_map>
#include "utils.h"

Pe ParsePeImage(LPCSTR imageName) {
    Pe pe;
    // would recommend workaround on loadlibrarya theres repos for it, but im not trying to make this really evasive, as its stands for PoC
    HMODULE hModule = LoadLibraryA(imageName);
    if (!hModule) {
        std::cerr << "Failed to load module: " << imageName << std::endl;
        return pe;
    }

    pe.ImageBase = hModule;
    pe.DosHeader = (PIMAGE_DOS_HEADER)hModule;
    pe.NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pe.DosHeader->e_lfanew);
    pe.OptionalHeader = pe.NtHeaders->OptionalHeader;
    pe.FileHeader = pe.NtHeaders->FileHeader;

    pe.ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(
        (DWORD_PTR)hModule + pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    pe.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (DWORD_PTR)hModule + pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    return pe;
}

DWORD GetSSN(PBYTE fnAddr) {
    for (WORD offset = 0;; offset++) {
        if (fnAddr[offset] == 0xE9) return NULL; // JMP detected
        if (fnAddr[offset] == 0xB8) return *(PDWORD)(fnAddr + offset + 1); // MOV EAX, SSN
    }
}

std::vector<SystemCall> GetSystemCalls() {
    std::vector<SystemCall> systemCalls;

    Pe peImage = ParsePeImage("ntoskrnl.exe");

    auto exportDirectory = peImage.ExportDirectory;
    auto peBase = (DWORD_PTR)peImage.ImageBase;

    PDWORD funcNames = (PDWORD)(peBase + exportDirectory->AddressOfNames);
    PDWORD funcAddrs = (PDWORD)(peBase + exportDirectory->AddressOfFunctions);
    PWORD funcNameOrds = (PWORD)(peBase + exportDirectory->AddressOfNameOrdinals);

    for (size_t i = 0; i < exportDirectory->NumberOfFunctions; i++) {
        LPCSTR fnName = (LPCSTR)(peBase + funcNames[i]);
        WORD fnOrd = (WORD)(funcNameOrds[i]);
        DWORD fnRva = (DWORD)(funcAddrs[fnOrd]);

        PBYTE fnAddr = (PBYTE)(peBase + fnRva);

        if (!_strnicmp(fnName, "Zw", 2)) {
            DWORD ssn = GetSSN(fnAddr);
            systemCalls.push_back({ fnName, ssn });
        }
    }

    return systemCalls;
}

SystemCall LookUpByHash(DWORD64 hash, const std::unordered_map<DWORD64, SystemCall>& systemCallMap) {
    auto it = systemCallMap.find(hash);
    if (it != systemCallMap.end()) {
        return it->second;
    }
    return { nullptr, 0 };
}

void Evilbytecode_SSN_Resolver(const std::vector<std::string>& functionNames) {
    auto systemCalls = GetSystemCalls();

    std::unordered_map<DWORD64, SystemCall> systemCallMap;
    for (const auto& systemCall : systemCalls) {
        DWORD64 hash = djb2((PBYTE)systemCall.fnName);
        systemCallMap[hash] = systemCall;
    }

    std::cout << "\n[=== EVILBYTECODE SSN RESOLVER ===]\n";
    std::cout << "NAME | SSN \n";
    std::cout << "-----------------------------------\n";

    for (const auto& fnName : functionNames) {
        DWORD64 hash = djb2((PBYTE)fnName.c_str());
        auto it = systemCallMap.find(hash);

        if (it != systemCallMap.end()) {
            const auto& result = it->second;
            std::cout << fnName << " | 0x" << std::hex << result.Ssn << std::dec << "\n";
        }
        else {
            std::cout << fnName << " | Not Found\n";
        }
    }
}
