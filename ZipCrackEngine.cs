using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ZipCrackerUI
{
    public class ZipCrackEngine
    {
        // Events for UI updates
        public event Action<string> OnLog;
        public event Action<string> OnPasswordTested;
        public event Action<long, long> OnProgress; // current, total
        public event Action<string> OnPasswordFound;
        public event Action<string> OnStatusChanged;

        // Statistics
        private long _totalAttempts;
        private long _skippedPasswords;
        private long _candidatesFound;
        public long TotalAttempts => _totalAttempts;
        public long SkippedPasswords => _skippedPasswords;
        public long CandidatesFound => _candidatesFound;
        public long TotalPossiblePasswords { get; private set; }
        public bool IsRunning { get; private set; }
        public DateTime StartTime { get; private set; }

        // Configuration
        public string ZipFilePath { get; set; }
        public int ThreadCount { get; set; } = Environment.ProcessorCount;
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 8;
        public string CustomPattern { get; set; }
        public bool EnableUtf8 { get; set; } = false;

        // Function to check if password was already tested (skip duplicates)
        public Func<string, bool> IsPasswordTestedFunc { get; set; }

        // Internal
        private CancellationTokenSource _cts;
        private byte[] _encryptedHeader;
        private uint _expectedCrcHigh;
        private ushort _expectedModTime;
        private string _foundPassword;
        private bool _passwordFound;
        private readonly object _lockObj = new object();

        // Archive type detection
        public string ArchiveType { get; private set; } = "Unknown";
        public bool IsRarArchive { get; private set; }

        // Pre-computed CRC32 table
        private static readonly uint[] Crc32Table = GenerateCrc32Table();

        public ZipCrackEngine()
        {
        }

        public bool LoadZipFile(string path)
        {
            ZipFilePath = path;
            IsRarArchive = false;
            ArchiveType = "Unknown";

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var br = new BinaryReader(fs);

                string ext = Path.GetExtension(path).ToLowerInvariant();

                // For SFX/EXE/RAR files, scan for ZIP or RAR signatures
                if (ext == ".exe" || ext == ".ico" || ext == ".sfx" || ext == ".rar")
                {
                    Log($"Scanning file for embedded archive...");
                }

                while (fs.Position < fs.Length - 30)
                {
                    long currentPos = fs.Position;
                    var sig = br.ReadUInt32();

                    // Check for ZIP signature (PK\x03\x04)
                    if (sig == 0x04034b50)
                    {
                        ArchiveType = "ZIP/PKZIP";

                        var version = br.ReadUInt16();
                        var flags = br.ReadUInt16();
                        br.ReadUInt16(); // compression
                        var modTime = br.ReadUInt16();
                        br.ReadUInt16(); // modDate
                        var crc32 = br.ReadUInt32();
                        var compSize = br.ReadUInt32();
                        br.ReadUInt32(); // uncompSize
                        var fnLen = br.ReadUInt16();
                        var extraLen = br.ReadUInt16();

                        var fileName = Encoding.ASCII.GetString(br.ReadBytes(fnLen));
                        fs.Position += extraLen;

                        if ((flags & 1) == 1 && compSize > 12)
                        {
                            _encryptedHeader = br.ReadBytes(12);
                            _expectedCrcHigh = (crc32 >> 24) & 0xFF;
                            _expectedModTime = modTime;

                            Log($"Loaded: {Path.GetFileName(path)}");
                            Log($"Archive type: {ArchiveType}");
                            Log($"First encrypted file: {fileName}");
                            Log($"CRC check byte: 0x{_expectedCrcHigh:X2}");
                            Log($"Encryption: PKZIP Traditional");

                            return true;
                        }

                        if (compSize > 0 && (flags & 1) == 0)
                            fs.Position += compSize;

                        continue;
                    }

                    // Check for RAR4 signature: "Rar!" (0x52617221) followed by 0x1A07
                    // RAR4: 52 61 72 21 1A 07 00
                    // RAR5: 52 61 72 21 1A 07 01 00
                    if (sig == 0x21726152) // "Rar!" in little-endian
                    {
                        // Read next 3 bytes to verify RAR signature
                        if (fs.Position + 3 <= fs.Length)
                        {
                            byte b1 = br.ReadByte(); // Should be 0x1A
                            byte b2 = br.ReadByte(); // Should be 0x07
                            byte b3 = br.ReadByte(); // 0x00 for RAR4, 0x01 for RAR5

                            if (b1 == 0x1A && b2 == 0x07)
                            {
                                IsRarArchive = true;
                                ArchiveType = b3 == 0x01 ? "RAR5" : "RAR4";

                                Log($"Loaded: {Path.GetFileName(path)}");
                                Log($"Archive type: {ArchiveType}");
                                Log($"Note: RAR encryption detected, will use WinRAR for verification");
                                Log($"Encryption: RAR AES-256 (will brute-force with WinRAR)");

                                // For RAR, we need to use external tools (WinRAR/UnRAR)
                                // Set dummy values - actual cracking will be done by testing with WinRAR
                                _encryptedHeader = new byte[12];
                                _expectedCrcHigh = 0;
                                _expectedModTime = 0;

                                return true;
                            }
                        }
                    }

                    fs.Position = currentPos + 1; // Move back and scan byte by byte
                }

                Log("ERROR: No encrypted files found in archive");
                return false;
            }
            catch (Exception ex)
            {
                Log($"ERROR: {ex.Message}");
                return false;
            }
        }

        public async Task StartAttackAsync(AttackMode mode)
        {
            if (_encryptedHeader == null)
            {
                Log("ERROR: No ZIP file loaded");
                return;
            }

            _cts = new CancellationTokenSource();
            IsRunning = true;
            _passwordFound = false;
            _foundPassword = null;
            _totalAttempts = 0;
            _skippedPasswords = 0;
            _candidatesFound = 0;
            StartTime = DateTime.Now;

            // Calculate total possible passwords for progress
            TotalPossiblePasswords = CalculateTotalPasswords(mode);

            OnStatusChanged?.Invoke("Running");
            Log($"Starting {mode} attack with {ThreadCount} threads...");
            Log($"Password length: {MinLength} - {MaxLength}");
            Log($"Total possible passwords: {TotalPossiblePasswords:N0}");

            try
            {
                switch (mode)
                {
                    case AttackMode.Smart:
                        await SmartAttackAsync();
                        break;
                    case AttackMode.Dictionary:
                        await DictionaryAttackAsync();
                        break;
                    case AttackMode.BruteForceNumbers:
                        await BruteForceAsync("0123456789");
                        break;
                    case AttackMode.BruteForceLowercase:
                        await BruteForceAsync("abcdefghijklmnopqrstuvwxyz");
                        break;
                    case AttackMode.BruteForceAlphanumeric:
                        await BruteForceAsync("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
                        break;
                    case AttackMode.BruteForceAll:
                        await BruteForceAsync("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=");
                        break;
                    case AttackMode.Pattern:
                        await PatternAttackAsync();
                        break;
                }

                if (_passwordFound)
                {
                    OnStatusChanged?.Invoke("Found!");
                    OnPasswordFound?.Invoke(_foundPassword);
                    Log($"");
                    Log($"========================================");
                    Log($"PASSWORD FOUND: {_foundPassword}");
                    Log($"========================================");
                }
                else if (!_cts.Token.IsCancellationRequested)
                {
                    OnStatusChanged?.Invoke("Not Found");
                    Log("Password not found in the tested combinations.");
                }
            }
            catch (OperationCanceledException)
            {
                OnStatusChanged?.Invoke("Stopped");
                Log("Attack stopped by user.");
            }
            finally
            {
                IsRunning = false;
            }
        }

        private bool _isPaused = false;
        private readonly object _pauseLock = new object();

        public void Pause()
        {
            lock (_pauseLock)
            {
                _isPaused = true;
                Log("Engine paused");
            }
        }

        public void Resume()
        {
            lock (_pauseLock)
            {
                _isPaused = false;
                Monitor.PulseAll(_pauseLock);
                Log("Engine resumed");
            }
        }

        public void Stop()
        {
            _cts?.Cancel();
            Resume(); // Resume if paused to allow clean exit
            Log("Stopping...");
        }

        private async Task SmartAttackAsync()
        {
            Log("");
            Log("[Phase 1] Testing known passwords...");

            // Known passwords from autorun.exe
            var knownPasswords = new[]
            {
                "c0qmp9w48rmualzskdfjvn091287n5crp0um1",
                "p920c8u4enoq)(&b(*&%v334&^",
                "xyht25nHg4f52sLo0mw4Ji84ki3qi",
                "gamehouse", "GameHouse", "GAMEHOUSE",
                "gamehouse2017", "GameHouse2017",
                "password", "Password", "PASSWORD",
                "admin", "Admin", "123456", "12345678",
            };

            foreach (var pwd in knownPasswords)
            {
                if (_cts.Token.IsCancellationRequested || _passwordFound) break;
                await TestAndVerifyAsync(pwd);
            }

            if (_passwordFound) return;

            Log("");
            Log("[Phase 2] Testing GameHouse patterns...");
            await TestGamePatternsAsync();

            if (_passwordFound) return;

            Log("");
            Log("[Phase 3] Testing substrings of known passwords...");
            await TestSubstringsAsync();

            if (_passwordFound) return;

            Log("");
            Log("[Phase 4] Brute force numbers (1-10 digits)...");
            await BruteForceAsync("0123456789", 1, 10);

            if (_passwordFound) return;

            Log("");
            Log("[Phase 5] Brute force lowercase (1-6 chars)...");
            await BruteForceAsync("abcdefghijklmnopqrstuvwxyz", 1, 6);
        }

        private async Task TestGamePatternsAsync()
        {
            var baseWords = new[] {
                "gamehouse", "GameHouse", "GAMEHOUSE", "gh", "GH",
                "autoplay", "AutoPlay", "game", "Game", "play", "Play",
                "3dknifflis", "knifflis", "sfx", "zip", "rar"
            };

            var suffixes = new[] { "", "!", "@", "#", "123", "1234", "2017", "2016", "17", "16" };

            foreach (var word in baseWords)
            {
                foreach (var suffix in suffixes)
                {
                    if (_cts.Token.IsCancellationRequested || _passwordFound) break;
                    await TestAndVerifyAsync(word + suffix);
                    await TestAndVerifyAsync(suffix + word);
                }
            }
        }

        private async Task TestSubstringsAsync()
        {
            var longPwds = new[] {
                "c0qmp9w48rmualzskdfjvn091287n5crp0um1",
                "xyht25nHg4f52sLo0mw4Ji84ki3qi"
            };

            foreach (var longPwd in longPwds)
            {
                for (int len = 4; len <= Math.Min(16, longPwd.Length); len++)
                {
                    for (int start = 0; start <= longPwd.Length - len; start++)
                    {
                        if (_cts.Token.IsCancellationRequested || _passwordFound) break;
                        await TestAndVerifyAsync(longPwd.Substring(start, len));
                    }
                }
            }
        }

        private async Task DictionaryAttackAsync()
        {
            var passwords = GenerateDictionary();
            long total = passwords.Count;

            Log($"Testing {total:N0} passwords from dictionary...");

            await Task.Run(() =>
            {
                Parallel.ForEach(passwords,
                    new ParallelOptions { MaxDegreeOfParallelism = ThreadCount, CancellationToken = _cts.Token },
                    (pwd, state) =>
                    {
                        // Check if paused
                        while (_isPaused && !_cts.Token.IsCancellationRequested)
                        {
                            lock (_pauseLock)
                            {
                                Monitor.Wait(_pauseLock, 100);
                            }
                        }

                        if (_passwordFound) { state.Stop(); return; }

                        // TestPasswordFast already increments _totalAttempts
                        if (TestPasswordFast(pwd))
                        {
                            if (VerifyPassword(pwd))
                            {
                                lock (_lockObj)
                                {
                                    _passwordFound = true;
                                    _foundPassword = pwd;
                                }
                                state.Stop();
                            }
                        }

                        // Update UI periodically
                        long count = _totalAttempts;
                        if (count % 10000 == 0)
                        {
                            OnProgress?.Invoke(count, total);
                        }
                    });
            }, _cts.Token);
        }

        private async Task BruteForceAsync(string charset, int? minLen = null, int? maxLen = null)
        {
            int min = minLen ?? MinLength;
            int max = maxLen ?? MaxLength;

            for (int len = min; len <= max && !_passwordFound && !_cts.Token.IsCancellationRequested; len++)
            {
                long combinations = (long)Math.Pow(charset.Length, len);
                Log($"Length {len}: {combinations:N0} combinations");

                await BruteForceLengthAsync(charset, len, combinations);
            }
        }

        private async Task BruteForceLengthAsync(string charset, int length, long totalCombinations)
        {
            int charsetLen = charset.Length;
            long lastUpdate = 0;

            await Task.Run(() =>
            {
                try
                {
                    // Partition by first character for parallel processing
                    Parallel.For(0, charsetLen,
                        new ParallelOptions { MaxDegreeOfParallelism = ThreadCount, CancellationToken = _cts.Token },
                        firstChar =>
                        {
                        if (_passwordFound) return;

                        // Check if paused at start
                        while (_isPaused && !_cts.Token.IsCancellationRequested)
                        {
                            lock (_pauseLock)
                            {
                                Monitor.Wait(_pauseLock, 100);
                            }
                        }

                        var indices = new int[length];
                        indices[0] = firstChar;
                        var password = new char[length];
                        password[0] = charset[firstChar];

                        // Local counter for batched updates
                        int localCount = 0;

                        while (!_passwordFound && !_cts.Token.IsCancellationRequested)
                        {
                            // Check if paused (less frequently - every 10000 iterations)
                            if (localCount % 10000 == 0 && _isPaused)
                            {
                                while (_isPaused && !_cts.Token.IsCancellationRequested)
                                {
                                    lock (_pauseLock)
                                    {
                                        Monitor.Wait(_pauseLock, 100);
                                    }
                                }
                            }

                            // Build password
                            for (int i = 1; i < length; i++)
                                password[i] = charset[indices[i]];

                            string pwd = new string(password);

                            // TestPasswordFast already increments _totalAttempts
                            if (TestPasswordFast(pwd))
                            {
                                Interlocked.Increment(ref _candidatesFound);

                                if (VerifyPassword(pwd))
                                {
                                    lock (_lockObj)
                                    {
                                        _passwordFound = true;
                                        _foundPassword = pwd;
                                    }
                                    return;
                                }
                            }

                            localCount++;

                            // Update UI periodically (every 50000 for responsiveness)
                            if (localCount % 50000 == 0)
                            {
                                long current = Interlocked.Read(ref _totalAttempts);
                                // Only update if significantly changed
                                if (current - Interlocked.Read(ref lastUpdate) > 10000)
                                {
                                    Interlocked.Exchange(ref lastUpdate, current);
                                    OnPasswordTested?.Invoke(pwd);
                                    OnProgress?.Invoke(current, totalCombinations);
                                }
                            }

                            // Increment from position 1
                            int pos = length - 1;
                            while (pos >= 1)
                            {
                                indices[pos]++;
                                if (indices[pos] < charsetLen) break;
                                indices[pos] = 0;
                                pos--;
                            }

                            if (pos < 1) break;
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    // Expected when user cancels - swallow it here
                }
            });
            // Note: _totalAttempts is already incremented in TestPasswordFast
        }

        private async Task PatternAttackAsync()
        {
            if (string.IsNullOrEmpty(CustomPattern))
            {
                Log("ERROR: No pattern specified");
                return;
            }

            Log($"Pattern: {CustomPattern}");
            Log("? = any lowercase letter, # = any digit");

            var passwords = GenerateFromPattern(CustomPattern);
            Log($"Generated {passwords.Count:N0} passwords from pattern");

            long total = passwords.Count;

            await Task.Run(() =>
            {
                Parallel.ForEach(passwords,
                    new ParallelOptions { MaxDegreeOfParallelism = ThreadCount, CancellationToken = _cts.Token },
                    (pwd, state) =>
                    {
                        // Check if paused
                        while (_isPaused && !_cts.Token.IsCancellationRequested)
                        {
                            lock (_pauseLock)
                            {
                                Monitor.Wait(_pauseLock, 100);
                            }
                        }

                        if (_passwordFound) { state.Stop(); return; }

                        // TestPasswordFast already increments _totalAttempts
                        if (TestPasswordFast(pwd))
                        {
                            if (VerifyPassword(pwd))
                            {
                                lock (_lockObj)
                                {
                                    _passwordFound = true;
                                    _foundPassword = pwd;
                                }
                                state.Stop();
                            }
                        }

                        // Update UI periodically
                        long count = _totalAttempts;
                        if (count % 1000 == 0)
                        {
                            OnPasswordTested?.Invoke(pwd);
                            OnProgress?.Invoke(count, total);
                        }
                    });
            }, _cts.Token);
            // Note: _totalAttempts is already incremented in TestPasswordFast
        }

        private async Task TestAndVerifyAsync(string password)
        {
            OnPasswordTested?.Invoke(password);

            // TestPasswordFast already increments _totalAttempts
            if (TestPasswordFast(password))
            {
                _candidatesFound++;
                Log($"Candidate: {password}");

                if (await Task.Run(() => VerifyPassword(password)))
                {
                    _passwordFound = true;
                    _foundPassword = password;
                }
            }
        }

        private bool TestPasswordFast(string password)
        {
            // Skip if already tested
            if (IsPasswordTestedFunc != null && IsPasswordTestedFunc(password))
            {
                Interlocked.Increment(ref _skippedPasswords);
                return false;
            }

            Interlocked.Increment(ref _totalAttempts);

            // For RAR archives, we can't do fast header check
            // We need to verify with WinRAR directly
            if (IsRarArchive)
            {
                // For RAR, always return true to verify with WinRAR
                // This is slower but necessary for RAR encryption
                return true;
            }

            // PKZIP key initialization
            uint key0 = 0x12345678;
            uint key1 = 0x23456789;
            uint key2 = 0x34567890;

            foreach (char c in password)
            {
                key0 = Crc32Table[(key0 ^ (byte)c) & 0xFF] ^ (key0 >> 8);
                key1 = (key1 + (key0 & 0xFF)) * 134775813 + 1;
                key2 = Crc32Table[(key2 ^ (byte)(key1 >> 24)) & 0xFF] ^ (key2 >> 8);
            }

            // Decrypt 12-byte header
            byte lastByte = 0;
            for (int i = 0; i < 12; i++)
            {
                ushort temp = (ushort)(key2 | 2);
                byte decByte = (byte)((temp * (temp ^ 1)) >> 8);
                lastByte = (byte)(_encryptedHeader[i] ^ decByte);

                key0 = Crc32Table[(key0 ^ lastByte) & 0xFF] ^ (key0 >> 8);
                key1 = (key1 + (key0 & 0xFF)) * 134775813 + 1;
                key2 = Crc32Table[(key2 ^ (byte)(key1 >> 24)) & 0xFF] ^ (key2 >> 8);
            }

            return lastByte == _expectedCrcHigh || lastByte == (byte)(_expectedModTime >> 8);
        }

        // Store compression type for hashcat mode selection
        public int CompressionType { get; private set; }

        /// <summary>
        /// Extract hash in Hashcat format using HashFormatDetector
        /// Automatically detects: PKZIP, WinZip AES, RAR3, RAR5, 7-Zip
        /// </summary>
        public string ExtractHashcatHash()
        {
            if (string.IsNullOrEmpty(ZipFilePath) || !File.Exists(ZipFilePath))
                return null;

            // ใช้ HashFormatDetector แทน
            var hashInfo = HashFormatDetector.ExtractHash(ZipFilePath);

            if (!hashInfo.IsValid)
            {
                Log($"ERROR: {hashInfo.ErrorMessage}");
                return null;
            }

            Log($"Hash Type: {hashInfo.Type}");
            Log($"Hashcat Mode: {hashInfo.HashcatMode} ({HashFormatDetector.GetHashcatModeDescription(hashInfo.HashcatMode)})");
            Log($"File: {hashInfo.FileName}");

            if (hashInfo.CompressionType > 0)
            {
                Log($"Compression: {hashInfo.CompressionType} ({HashFormatDetector.GetCompressionName(hashInfo.CompressionType)})");
            }

            // อัปเดต CompressionType เพื่อใช้ใน MainWindow
            CompressionType = hashInfo.CompressionType;

            return hashInfo.Hash;
        }

        // Old ExtractWinZipAESHash, IsWinZipAES, and ExtractRarHash methods removed
        // Now using HashFormatDetector.ExtractHash() which handles all formats

        public bool VerifyPassword(string password)
        {
            // Try to find WinRAR or UnRAR in common locations
            string[] possiblePaths = {
                @"C:\Program Files\WinRAR\UnRAR.exe",
                @"C:\Program Files\WinRAR\WinRAR.exe",
                @"C:\Program Files\WinRAR\Rar.exe",
                @"C:\Program Files (x86)\WinRAR\UnRAR.exe",
                @"C:\Program Files (x86)\WinRAR\WinRAR.exe",
                @"D:\Program Files\WinRAR\UnRAR.exe",
                @"D:\Program Files\WinRAR\WinRAR.exe",
            };

            string extractorPath = null;
            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    extractorPath = path;
                    break;
                }
            }

            if (extractorPath == null)
            {
                Log("WARNING: WinRAR not found at C:\\Program Files\\WinRAR\\");
                return false;
            }

            try
            {
                var tempDir = Path.Combine(Path.GetTempPath(), "archivetest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(tempDir);

                string args;
                if (extractorPath.Contains("UnRAR"))
                {
                    // UnRAR command line: unrar x -p<password> -y archive.rar destination\
                    args = $"x -p\"{password}\" -y -o+ \"{ZipFilePath}\" \"{tempDir}\\\"";
                }
                else
                {
                    // WinRAR command line
                    args = $"x -ibck -y -p\"{password}\" \"{ZipFilePath}\" \"{tempDir}\\\"";
                }

                var psi = new ProcessStartInfo
                {
                    FileName = extractorPath,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                if (!process.WaitForExit(30000))
                {
                    try { process.Kill(); } catch { }
                    try { Directory.Delete(tempDir, true); } catch { }
                    return false;
                }

                // Check exit code - 0 means success
                int exitCode = process.ExitCode;

                // Check if files were extracted
                var files = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories);
                bool success = exitCode == 0 && files.Length >= 1;

                // Cleanup
                try { Directory.Delete(tempDir, true); } catch { }

                return success;
            }
            catch (Exception ex)
            {
                Log($"Verify error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Calculate total possible passwords based on attack mode
        /// </summary>
        private long CalculateTotalPasswords(AttackMode mode)
        {
            long total = 0;

            switch (mode)
            {
                case AttackMode.Smart:
                    // Dictionary + Numbers + Common patterns (estimate)
                    total = 10000000 + 100; // 10M numbers + common words
                    break;

                case AttackMode.Dictionary:
                    total = 10000000 + 100; // 10M numbers + common words
                    break;

                case AttackMode.BruteForceNumbers:
                    // Sum of 10^i for i from MinLength to MaxLength
                    for (int len = MinLength; len <= MaxLength; len++)
                        total += (long)Math.Pow(10, len);
                    break;

                case AttackMode.BruteForceLowercase:
                    // Sum of 26^i for i from MinLength to MaxLength
                    for (int len = MinLength; len <= MaxLength; len++)
                        total += (long)Math.Pow(26, len);
                    break;

                case AttackMode.BruteForceAlphanumeric:
                    // Sum of 62^i for i from MinLength to MaxLength
                    for (int len = MinLength; len <= MaxLength; len++)
                        total += (long)Math.Pow(62, len);
                    break;

                case AttackMode.BruteForceAll:
                    // Sum of 77^i for i from MinLength to MaxLength
                    // 77 = 26 + 26 + 10 + 15 special chars
                    for (int len = MinLength; len <= MaxLength; len++)
                        total += (long)Math.Pow(77, len);
                    break;

                case AttackMode.Pattern:
                    // Pattern attack - estimate based on pattern
                    if (!string.IsNullOrEmpty(CustomPattern))
                    {
                        int unknowns = 0;
                        foreach (char c in CustomPattern)
                            if (c == '?') unknowns++;
                        // Each ? can be 0-9, a-z, A-Z = 62 possibilities
                        total = (long)Math.Pow(62, unknowns);
                    }
                    else
                    {
                        total = 1000000; // Default estimate
                    }
                    break;

                default:
                    total = 1000000;
                    break;
            }

            return total;
        }

        private List<string> GenerateDictionary()
        {
            var list = new List<string>();

            // Common passwords
            list.AddRange(new[] {
                "password", "Password", "PASSWORD", "pass", "123456", "12345678",
                "admin", "Admin", "qwerty", "abc123", "letmein", "welcome",
                "gamehouse", "GameHouse", "GAMEHOUSE", "gamehouse2017",
                "autoplay", "AutoPlay", "game", "Game", "sfx", "zip"
            });

            // Numbers
            for (int i = 0; i <= 9999999; i++)
            {
                list.Add(i.ToString());
            }

            return list;
        }

        private List<string> GenerateFromPattern(string pattern)
        {
            var results = new List<string> { "" };
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string digits = "0123456789";

            foreach (char c in pattern)
            {
                var newResults = new List<string>();

                if (c == '?')
                {
                    foreach (var r in results)
                        foreach (var ch in lowercase)
                            newResults.Add(r + ch);
                }
                else if (c == '#')
                {
                    foreach (var r in results)
                        foreach (var ch in digits)
                            newResults.Add(r + ch);
                }
                else
                {
                    foreach (var r in results)
                        newResults.Add(r + c);
                }

                results = newResults;

                // Limit to prevent memory issues
                if (results.Count > 10000000)
                {
                    Log("WARNING: Pattern generates too many passwords, limiting...");
                    break;
                }
            }

            return results;
        }

        private void Log(string message)
        {
            OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}");
        }

        private static uint[] GenerateCrc32Table()
        {
            var table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 0; j < 8; j++)
                    crc = (crc & 1) == 1 ? (crc >> 1) ^ 0xEDB88320 : crc >> 8;
                table[i] = crc;
            }
            return table;
        }
    }

    public enum AttackMode
    {
        Smart,
        Dictionary,
        BruteForceNumbers,
        BruteForceLowercase,
        BruteForceAlphanumeric,
        BruteForceAll,
        Pattern
    }
}
