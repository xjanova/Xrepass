# X-Repass - Archive Password Recovery Tool

Professional archive password recovery tool with CPU and GPU acceleration.

## Features

- **Multi-engine Support**: CPU brute-force + GPU acceleration via Hashcat
- **Archive Types**: ZIP (PKZIP, WinZip AES), RAR3, RAR5, 7-Zip, SFX
- **Attack Modes**: Smart, Dictionary, Brute-force (Numbers/Lowercase/Alphanumeric/All), Pattern
- **Progress Tracking**: Real-time progress based on tested passwords
- **Session Persistence**: Resume interrupted sessions
- **Temperature Monitoring**: CPU/GPU temperature display
- **Modern UI**: Neon-themed interface with animations

## Requirements

- Windows 10/11
- .NET 8.0 Runtime
- (Optional) Hashcat for GPU acceleration
- (Optional) WinRAR for RAR verification

## Build

```bash
dotnet build
dotnet run
```

## Usage

1. Open archive file (ZIP, RAR, 7z, or SFX)
2. Select attack mode and password length range
3. Enable CPU/GPU modes
4. Click START

## Architecture

| File | Description |
|------|-------------|
| `MainWindow.xaml.cs` | Main UI and coordination |
| `ZipCrackEngine.cs` | CPU cracking engine |
| `HashFormatDetector.cs` | Archive hash extraction |
| `DatabaseManager.cs` | SQLite session storage |

## License

Copyright 2024 XMan Studio. All rights reserved.
