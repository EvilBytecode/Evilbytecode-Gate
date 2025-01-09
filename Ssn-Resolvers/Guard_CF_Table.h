#ifndef GUARD_CF_TABLE_H
#define GUARD_CF_TABLE_H

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>

struct GuardTableEntry {
    DWORD64 dwHash;
    WORD wSystemCall;
    PVOID functionAddress;
};

std::vector<GuardTableEntry> GetAllGuardEntries();
GuardTableEntry LookUpByHash(DWORD64 dwHash, const std::vector<GuardTableEntry>& entries);
void GuardCF_SSN_Resolver(const std::vector<std::string>& functionNames);

#endif // GUARD_CF_TABLE_H
