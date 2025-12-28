# GPU Hash Format Fix - WinZip AES

## Date: 2025-12-28

## Problem
GPU mode (hashcat) was skipping short password lengths (Queue 5/8 instead of 1/8), causing it to miss simple 1-2 character passwords that CPU mode could find.

## Root Cause
**AES Strength offset was read incorrectly in HashFormatDetector.cs**

WinZip AES Extra Field structure:
```
Offset 0-1: Header ID (0x9901 = bytes 01 99 in little-endian)
Offset 2-3: Data size (usually 7)
Offset 4-5: AES version (0x0001 or 0x0002)
Offset 6-7: Vendor ID ("AE" = 0x4145)
Offset 8:   AES strength (1=128, 2=192, 3=256) ← CORRECT
Offset 9-10: Actual compression method
```

**Bug:** Code was reading `extraData[i + 4]` which returned AES version (2) instead of AES strength (3).

This caused:
- Salt size calculated as 12 bytes (AES-192) instead of 16 bytes (AES-256)
- Hash format was malformed
- Hashcat couldn't verify short passwords correctly

## Fix Applied

### HashFormatDetector.cs (line 366-373)
```csharp
// Before (WRONG):
if (i + 4 < extraData.Length)
    aesStrength = extraData[i + 4];

// After (CORRECT):
// AES strength is at offset i+8 (after header ID, size, version, vendor ID)
if (i + 8 < extraData.Length)
    aesStrength = extraData[i + 8];
```

### ZipCrackEngine.cs (line 116-117)
Same fix applied for consistency:
```csharp
if (i + 8 < extraData.Length)
    aesStrength = extraData[i + 8]; // AES strength: 1=128, 2=192, 3=256
```

## Additional Fix: GPU Pause/Resume

### Problem
Clicking Pause button only paused CPU engine, not hashcat process.

### Solution
1. Added `RedirectStandardInput = true` to hashcat ProcessStartInfo
2. Send `p` (pause) or `r` (resume) to hashcat stdin when button clicked

### MainWindow.xaml.cs changes:
```csharp
// ProcessStartInfo
RedirectStandardInput = true, // For pause/resume control

// BtnPause_Click - Pause GPU
if (_hashcatProcess != null && !_hashcatProcess.HasExited)
{
    _hashcatProcess.StandardInput.WriteLine("p");
    _hashcatProcess.StandardInput.Flush();
}

// BtnPause_Click - Resume GPU
if (_hashcatProcess != null && !_hashcatProcess.HasExited)
{
    _hashcatProcess.StandardInput.WriteLine("r");
    _hashcatProcess.StandardInput.Flush();
}
```

## Result
- GPU mode now starts from Queue 1/8 (password length 1)
- Hashcat can correctly verify all password lengths
- GPU cracking is now much faster than CPU for WinZip AES
- Pause/Resume works for both CPU and GPU modes

## Files Modified
- `HashFormatDetector.cs` - Fixed AES strength offset
- `ZipCrackEngine.cs` - Fixed AES strength offset (consistency)
- `MainWindow.xaml.cs` - Added GPU pause/resume support
