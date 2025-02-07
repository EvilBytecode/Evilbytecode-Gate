
# Evilbytecode-Gate
- https://t.me/+TRYMuOVDiWA4MjM0
Evilbytecode-Gate provides two mechanisms for resolving System Service Numbers (SSNs) of Windows API functions:
1. **Control Flow (CF) Way**: Using the Guard CF Table in `ntdll.dll`.
2. **By Parsing NTOSKRNL.EXE**: Resolving SSNs by analyzing the kernel export table.

## Features
- **Guard CF Table Resolution**: Extracts SSNs and function jump addresses from the Guard CF Table in `ntdll.dll`.
- **Kernel Export Parsing**: Analyzes `ntoskrnl.exe` to resolve SSNs for Zw-prefixed system calls.

## How It Works
1. **Guard CF Table Resolution**:
   - Parses the Guard CF Table in `ntdll.dll` to locate system calls.
   - Uses function RVA (Relative Virtual Address) to match exported Zw-prefixed functions.

2. **Parsing NTOSKRNL.EXE**:
   - Loads `ntoskrnl.exe` and iterates through its export table.
   - Identifies Zw-prefixed functions and parses their prologues to extract SSNs (`MOV EAX, SSN`).

## Finding Zw-Prefixed Functions
You can locate Zw-prefixed functions in `ntoskrnl.exe` using tools like:
- **IDA**: Search for "Zw".

Once located, analyze the function prologue to extract the SSN. Look for instructions like:
```
MOV EAX, <SSN>
SYSCALL
```

## Example Output
```
[=== GUARD CF TABLE SSN RESOLVER ===]
NAME                    | Number SSN | JumpAddress
---------------------------------------------------
ZwAllocateVirtualMemory | 24         | 00007FF9BCF1FA10
ZwWriteVirtualMemory    | 58         | 00007FF9BCF1FE50
ZwProtectVirtualMemory  | 80         | 00007FF9BCF20110
ZwCreateThreadEx        | 201        | 00007FF9BCF21020

[=== EVILBYTECODE SSN RESOLVER ===]
NAME                    | SSN
---------------------------------
ZwAllocateVirtualMemory | 0x18
ZwWriteVirtualMemory    | Not Found
ZwProtectVirtualMemory  | 0x50
ZwCreateThreadEx        | Not Found
```

## Note
This project is a **Proof of Concept** (PoC) and is not intended for malicious purposes.
EvilbytecodeGate wont get you every SSN, wouldnt really depend on it.
