#include "Guard_CF_Table.h"
#include "EvilbytecodeGate.h"

int main() {
    std::vector<std::string> guardcfssnsnames = {
        "ZwAllocateVirtualMemory",
        "ZwWriteVirtualMemory",
        "ZwProtectVirtualMemory",
        "ZwCreateThreadEx"
    };

    GuardCF_SSN_Resolver(guardcfssnsnames);
    Evilbytecode_SSN_Resolver(guardcfssnsnames);
    return 0;
}
