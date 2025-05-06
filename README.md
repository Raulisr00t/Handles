# 🔍 Handles - Process Handle Inspector

This tool enumerates and displays all open handles for a specific process in Windows. It provides detailed information including handle type, name (if available), and associated access rights in a readable format.

---

## 🛠 Features

- Enumerates handles for any target process
- Displays:
  - Handle value
  - Object type
  - Object name (if retrievable)
  - Human-readable Access Mask permissions
- Uses undocumented Windows APIs (`NtQuerySystemInformation`, `NtQueryObject`)

---

## 🚀 Usage

```powershell
Handles.exe <ProcessName>
```

### Example

```powershell
Handles.exe notepad.exe
```

## Output Example

```powershell
[+] PID: 1234
Handle: 0x0034  | Type: File | Name: \Device\HarddiskVolume2\Windows\notepad.exe
AccessMask: GENERIC_READ READ_CONTROL SYNCHRONIZE |
```

### 🧱 Build Instructions

Compile with a Windows-compatible C compiler (MSVC recommended):
```powershell
cl /FeHandles.exe main.c /link ntdll.lib psapi.lib
```

## Disclaimer

This tool uses undocumented system calls and may break on future versions of Windows. Use it for educational or diagnostic purposes only.
