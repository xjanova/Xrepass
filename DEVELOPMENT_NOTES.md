# X-Repass Development Notes

## Project Overview
Archive Password Recovery Tool - Professional Edition
- **Product**: X-Repass
- **Company**: XMan Studio
- **Version**: 1.0.0
- **Target Framework**: .NET 8.0 Windows (WPF)

---

## Known Issues & Solutions

### 1. Hashcat File Path Error
**Problem**: `[ERR] D:\Code\787.zip: No such file or directory`

**Cause**: Hashcat requires hash strings, not direct file paths for most modes.

**Solution** (HashFormatDetector.cs):
- Each archive type needs specific hash format extraction:
  - **PKZIP Traditional (Mode 17200-17230)**: `$pkzip2$*compression*...*$/pkzip2$`
  - **WinZip AES (Mode 13600)**: `$zip2$*type*mode*magic*salt*verify*compress_length*data*auth_length*auth*$/zip2$`
  - **RAR5 (Mode 13000)**: `$rar5$16$salt$15$checkvalue$8$kdfcount`
  - **RAR3 (Mode 12500)**: `$RAR3$*type*salt*encrypted_data`
  - **7-Zip (Mode 11600)**: Complex format - recommend using 7z2john tool

**Files Modified**:
- `HashFormatDetector.cs`: Added proper hash extraction for each format

---

### 2. Progress Bar Not Displaying
**Problem**: Progress bars show 0% when using GPU mode only

**Cause**: Progress bar update code was inside `if (_engine.IsRunning)` block, which only triggers for CPU mode

**Solution** (MainWindow.xaml.cs):
```csharp
// Separate CPU and GPU progress updates
bool cpuRunning = _engine.IsRunning;
bool gpuRunning = _hashcatProcess != null && !_hashcatProcess.HasExited;

// Update CPU progress bars (always)
progressBarCpu.Value = cpuProgress;
progressBarCpuLarge.Value = cpuProgress;

// Update GPU progress bars (from hashcat parsing)
double gpuProgress = Math.Min(_gpuProgress, 100);
progressBarGpu.Value = gpuProgress;
progressBarGpuLarge.Value = gpuProgress;

// Overall progress uses max of CPU/GPU when both running
if (cpuRunning && gpuRunning)
    currentProgress = Math.Max(cpuProgress, gpuProgress);
else if (cpuRunning || cpuProgress > 0)
    currentProgress = cpuProgress;
else if (gpuRunning || gpuProgress > 0)
    currentProgress = gpuProgress;
```

**Files Modified**:
- `MainWindow.xaml.cs`: InitializeTimer() - Timer tick handler

---

### 3. TextBox Values Not Visible
**Problem**: PASSWORD LENGTH, PATTERN, CPU THREADS fields - text invisible

**Cause**: Foreground color too similar to background, template not properly centering content

**Solution** (App.xaml):
```xml
<Style x:Key="ModernTextBox" TargetType="TextBox">
    <Setter Property="Background" Value="#1a1a2e"/>
    <Setter Property="Foreground" Value="#00f5ff"/>  <!-- Bright cyan -->
    <Setter Property="FontSize" Value="16"/>
    <Setter Property="FontWeight" Value="Bold"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
    <Setter Property="HorizontalContentAlignment" Value="Center"/>
</Style>
```

**Files Modified**:
- `App.xaml`: ModernTextBox style
- `MainWindow.xaml`: TextBox Height="40"

---

### 4. Button Text Cut Off
**Problem**: OPEN FILE button text was truncated

**Solution** (MainWindow.xaml):
- Increased button width: 70x32 → 130x40
- Separated icon and text with StackPanel
- Added proper margins and padding

---

### 5. App Icon Corrupt
**Problem**: XamlParseException - Image decoder cannot decode image

**Cause**: First app.ico was improperly formatted

**Solution**:
- Created proper ICO file with multiple resolutions (16, 32, 48, 256)
- Used PNG compression inside ICO format
- Script: `CreateIcon.ps1`

---

### 6. Program Crash on Close (TaskCanceledException)
**Problem**: App crashes when closing during active operation

**Solution** (MainWindow.xaml.cs):
```csharp
private void MainWindow_Closing(object sender, CancelEventArgs e)
{
    try
    {
        _engine?.Stop();
        _masterCts?.Cancel();
        _gpuCts?.Cancel();

        if (_hashcatProcess != null && !_hashcatProcess.HasExited)
        {
            try { _hashcatProcess.Kill(); } catch { }
            try { _hashcatProcess.WaitForExit(1000); } catch { }
        }

        _updateTimer?.Stop();
        _fireflyTimer?.Stop();

        // Kill any remaining hashcat processes
        foreach (var proc in Process.GetProcessesByName("hashcat"))
        {
            try { proc.Kill(); } catch { }
        }

        SaveSettings();
    }
    catch { }
}
```

---

### 7. Firefly Animation Not Visible
**Problem**: Fireflies too small and dim

**Solution** (MainWindow.xaml.cs):
- Increased size: 3-5px → 6-10px
- Changed from BlurEffect to DropShadowEffect
- Added RadialGradientBrush with white core
- Increased opacity: 0.3-1.0 → 0.6-1.0

---

### 8. Logo Watermark Not Visible
**Problem**: Background logo too transparent

**Solution** (MainWindow.xaml):
```xml
<Image Source="logo.png"
       Width="500" Height="500"
       Opacity="0.35"
       ...>
    <Image.Effect>
        <DropShadowEffect Color="#00f5ff" BlurRadius="80"
                          ShadowDepth="0" Opacity="0.5"/>
    </Image.Effect>
</Image>
```

---

### 9. Progress Bar Reaching 100% Too Fast
**Problem**: Progress bar วิ่งถึง 100% เร็วเกินไป ไม่ตรงกับความเป็นจริง

**Cause**:
1. นับจำนวนพาสเวิร์ดที่ผลิต (generated) แทนที่จะนับที่ทดสอบแล้ว (tested)
2. มีการนับซ้ำใน `BruteForceLengthAsync`, `PatternAttackAsync`, `DictionaryAttackAsync`

**Solution** (ZipCrackEngine.cs + MainWindow.xaml.cs):
```csharp
// MainWindow.xaml.cs - Timer tick handler
// Get CPU tested count (actually tested, not generated)
long cpuTestedCount = _engine.TotalAttempts;

// Calculate OVERALL progress
// Total tested = CPU tested + GPU tested
// Progress = (total tested / total possible) * 100
long totalTestedCount = cpuTestedCount + _gpuTestedCount;
double overallProgress = 0;

if (_totalPossiblePasswords > 0)
{
    overallProgress = (double)totalTestedCount / _totalPossiblePasswords * 100;
    overallProgress = Math.Min(overallProgress, 100);
}
```

**Concept**:
1. แบ่งช่วงงานออก คำนวณช่วงงานนี้เป็น 100%
2. นับจากที่ผ่านการทดสอบรหัสแล้วเท่านั้น (ผลิตมาแต่ยังไม่ทดสอบยังไม่นับ)
3. คิดจากจำนวนพาสเวิร์ดทั้งหมดที่เป็นไปได้
4. รวมกันทั้ง CPU+GPU สำหรับงานที่ทดสอบผ่านไปแล้ว

**Files Modified**:
- `MainWindow.xaml.cs`: Timer tick handler
- `ZipCrackEngine.cs`: Removed duplicate counting, `TestPasswordFast()` is single source of truth

---

### 10. CPU Cracking Slow for Simple Passwords
**Problem**: รหัสตัวเลข 4 หลักง่ายๆ ใช้เวลานาน

**Cause**:
1. UI update บ่อยเกินไป (ทุก modulo check)
2. Pause check ทุกรอบ

**Solution** (ZipCrackEngine.cs):
```csharp
// Local counter for batched updates
int localCount = 0;

// Check if paused (less frequently - every 10000 iterations)
if (localCount % 10000 == 0 && _isPaused) { ... }

// Update UI periodically (every 50000 for responsiveness)
if (localCount % 50000 == 0) { ... }
```

**Note**: สำหรับ RAR archives, CPU cracking ช้าเนื่องจากต้อง verify ด้วย WinRAR ทุกครั้ง (ไม่สามารถทำ fast header check ได้เหมือน ZIP) - แนะนำใช้ GPU mode สำหรับ RAR

---

## Hashcat Mode Reference

| Archive Type | Mode | Hash Format |
|-------------|------|-------------|
| PKZIP Deflate | 17200 | `$pkzip2$*...*$/pkzip2$` |
| PKZIP Store | 17210 | `$pkzip2$*...*$/pkzip2$` |
| PKZIP Deflate64 | 17220 | `$pkzip2$*...*$/pkzip2$` |
| PKZIP LZMA | 17225 | `$pkzip2$*...*$/pkzip2$` |
| WinZip AES | 13600 | `$zip2$*...*$/zip2$` |
| RAR3 | 12500 | `$RAR3$*type*salt*data` |
| RAR5 | 13000 | `$rar5$16$salt$15$check$8$count` |
| 7-Zip | 11600 | Complex - use 7z2john |

---

## File Structure

```
ZipCrackerUI/
├── MainWindow.xaml          # Main UI layout
├── MainWindow.xaml.cs       # Main code-behind
├── App.xaml                 # Application styles
├── HashFormatDetector.cs    # Archive hash extraction
├── ZipCrackEngine.cs        # CPU cracking engine
├── DatabaseManager.cs       # SQLite session storage
├── SettingsWindow.xaml      # Settings dialog
├── TestPasswordDialog.xaml  # Test password dialog
├── WorkChunkManager.cs      # Work distribution
├── TemperatureGraphHelper.cs # Temperature graph rendering
├── CreateIcon.ps1           # Icon generation script
├── logo.png                 # Application logo
├── app.ico                  # Application icon (multi-res)
└── DEVELOPMENT_NOTES.md     # This file
```

---

## Build Commands

```bash
# Build
dotnet build

# Run
dotnet run

# Publish (Release)
dotnet publish -c Release -r win-x64 --self-contained
```

---

## Future Improvements

1. [ ] Add support for extracting 7-Zip hashes directly (without 7z2john)
2. [ ] Add support for more RAR variants
3. [ ] Add dictionary attack mode for GPU
4. [ ] Add pause/resume for GPU attacks
5. [ ] Add estimated time remaining calculation
6. [ ] Add export/import session feature

---

## Change Log

### 2025-12-27 (Session 2)
- Fixed progress bar calculation - now counts only TESTED passwords, not generated
  - Overall progress = (CPU tested + GPU tested) / Total Possible Passwords * 100
  - CPU progress = CPU tested / CPU assigned work range * 100
  - GPU progress parsed from hashcat output
- Fixed duplicate counting in `_totalAttempts`
  - Removed duplicate `Interlocked.Add()` in `BruteForceLengthAsync`, `PatternAttackAsync`, `DictionaryAttackAsync`
  - `TestPasswordFast()` is now the single source of truth for counting tested passwords
- Improved CPU brute force performance
  - Added local counter for batched UI updates
  - Reduced pause check frequency (every 10000 iterations)
  - Reduced UI update frequency (every 50000 iterations)
- Fixed variable name errors in timer tick handler
  - Changed `totalAttempts` to `totalTestedCount`
  - Changed `currentProgress` to `overallProgress`

**Files Modified**:
- `MainWindow.xaml.cs`: Timer tick handler fixes
- `ZipCrackEngine.cs`: Progress counting and performance improvements

---

### 2024-12-27 (Session 1)
- Fixed hashcat file path issue - now extracts proper hash strings
- Fixed progress bar display for GPU-only mode
- Added proper cleanup on program close
- Enhanced firefly animation visibility
- Added logo watermark with glow effect
- Added version and license info in status bar
