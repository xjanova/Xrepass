using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
        public event Action<string> OnPatternChanged; // New: current pattern description

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
        public string CurrentPattern { get; private set; } = "Idle"; // Current pattern being tested

        // Configuration
        public string ZipFilePath { get; set; }
        public int ThreadCount { get; set; } = Environment.ProcessorCount;
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 8;
        public string CustomPattern { get; set; }
        public string CustomCharset { get; set; } // Charset from UI checkboxes
        public bool EnableUtf8 { get; set; } = false;
        public bool IsHybridMode { get; set; } = false; // CPU+GPU mode: CPU does only digits

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
        public bool Is7zArchive { get; private set; }

        // Pre-computed CRC32 table
        private static readonly uint[] Crc32Table = GenerateCrc32Table();

        public ZipCrackEngine()
        {
        }

        public bool LoadZipFile(string path)
        {
            ZipFilePath = path;
            IsRarArchive = false;
            Is7zArchive = false;
            ArchiveType = "Unknown";
            IsWinZipAES = false;
            _7zipWarningShown = false; // Reset warning flag for new file

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
                        var version = br.ReadUInt16();
                        var flags = br.ReadUInt16();
                        var compression = br.ReadUInt16();
                        var modTime = br.ReadUInt16();
                        br.ReadUInt16(); // modDate
                        var crc32 = br.ReadUInt32();
                        var compSize = br.ReadUInt32();
                        br.ReadUInt32(); // uncompSize
                        var fnLen = br.ReadUInt16();
                        var extraLen = br.ReadUInt16();

                        var fileName = Encoding.ASCII.GetString(br.ReadBytes(fnLen));

                        // Check extra field for WinZip AES (0x9901)
                        bool isAES = false;
                        int aesStrength = 0;
                        if (extraLen > 0)
                        {
                            var extraData = br.ReadBytes(extraLen);
                            for (int i = 0; i < extraData.Length - 4; i++)
                            {
                                if (extraData[i] == 0x01 && extraData[i + 1] == 0x99)
                                {
                                    isAES = true;
                                    if (i + 8 < extraData.Length)
                                        aesStrength = extraData[i + 8]; // AES strength: 1=128, 2=192, 3=256
                                    break;
                                }
                            }
                        }


                        // Check if encrypted
                        if ((flags & 1) == 1 && compSize > 12)
                        {
                            if (isAES || compression == 99) // WinZip AES uses compression method 99
                            {
                                // WinZip AES - use GPU (hashcat) for cracking
                                IsWinZipAES = true;
                                ArchiveType = $"WinZip AES-{(aesStrength == 1 ? 128 : aesStrength == 2 ? 192 : 256)}";

                                // Set dummy header - actual cracking done by hashcat
                                _encryptedHeader = new byte[12];
                                _expectedCrcHigh = 0;
                                _expectedModTime = 0;

                                Log($"Loaded: {Path.GetFileName(path)}");
                                Log($"Archive type: {ArchiveType}");
                                Log($"First encrypted file: {fileName}");
                                Log($"Encryption: WinZip AES (use GPU mode for best performance)");
                                Log($"⚠️ CPU mode for AES is very slow - recommend GPU only");

                                return true;
                            }
                            else
                            {
                                // Traditional PKZIP (ZipCrypto)
                                ArchiveType = "ZIP/PKZIP";
                                _encryptedHeader = br.ReadBytes(12);
                                _expectedCrcHigh = (crc32 >> 24) & 0xFF;
                                _expectedModTime = modTime;

                                Log($"Loaded: {Path.GetFileName(path)}");
                                Log($"Archive type: {ArchiveType}");
                                Log($"First encrypted file: {fileName}");
                                Log($"CRC check byte: 0x{_expectedCrcHigh:X2}");
                                Log($"Encryption: PKZIP Traditional (ZipCrypto)");

                                return true;
                            }
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

                    // Check for 7-Zip signature: 37 7A BC AF 27 1C (7z..)
                    // First 4 bytes: 0x377ABCAF in big-endian = 0xAFBC7A37 in little-endian
                    if (sig == 0xAFBC7A37)
                    {
                        // Read next 2 bytes to verify: 27 1C
                        if (fs.Position + 2 <= fs.Length)
                        {
                            byte b1 = br.ReadByte(); // Should be 0x27
                            byte b2 = br.ReadByte(); // Should be 0x1C

                            if (b1 == 0x27 && b2 == 0x1C)
                            {
                                Is7zArchive = true;
                                ArchiveType = "7-Zip";

                                Log($"Loaded: {Path.GetFileName(path)}");
                                Log($"Archive type: {ArchiveType}");
                                Log($"Encryption: 7-Zip AES-256 (use GPU mode)");
                                Log($"⚠️ 7-Zip requires GPU mode (Hashcat)");

                                // For 7z, we need hashcat for cracking
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

        // Flag for WinZip AES encryption
        public bool IsWinZipAES { get; private set; }

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
                // If CustomCharset is set, use progressive brute force with that charset
                if (!string.IsNullOrEmpty(CustomCharset))
                {
                    Log($"Using custom charset: {CustomCharset.Length} characters");
                    await ProgressiveBruteForceAsync(CustomCharset);
                }
                else
                {
                    // Fallback to mode-based selection
                    switch (mode)
                    {
                        case AttackMode.Smart:
                            await SmartAttackAsync();
                            break;
                        case AttackMode.Dictionary:
                            await DictionaryAttackAsync();
                            break;
                        case AttackMode.BruteForceNumbers:
                            await ProgressiveBruteForceAsync("0123456789");
                            break;
                        case AttackMode.BruteForceLowercase:
                            await ProgressiveBruteForceAsync("abcdefghijklmnopqrstuvwxyz");
                            break;
                        case AttackMode.BruteForceAlphanumeric:
                            await ProgressiveBruteForceAsync("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
                            break;
                        case AttackMode.BruteForceAll:
                            await ProgressiveBruteForceAsync("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=");
                            break;
                        case AttackMode.Pattern:
                            await PatternAttackAsync();
                            break;
                    }
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
            // Character sets ordered by probability
            const string DIGITS = "0123456789";
            const string LOWER = "abcdefghijklmnopqrstuvwxyz";
            const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string SPECIAL = "!@#$%^&*()_+-=";

            Log("");
            Log("[Phase 1] Testing common passwords...");

            // Common passwords - most frequently used
            var commonPasswords = new[]
            {
                // Top common passwords
                "123456", "password", "12345678", "qwerty", "123456789",
                "12345", "1234", "111111", "1234567", "dragon",
                "123123", "baseball", "iloveyou", "trustno1", "sunshine",
                "master", "welcome", "shadow", "ashley", "football",
                "jesus", "michael", "ninja", "mustang", "password1",
                "abc123", "letmein", "monkey", "696969", "batman",
                "admin", "Admin", "root", "test", "guest",
                // Numeric patterns
                "0000", "1111", "2222", "9999", "1212", "7777",
                "0123", "1234", "2345", "6789", "4321",
                "00000", "11111", "12321", "54321",
                "000000", "123321", "654321", "121212",
                // GameHouse specific
                "gamehouse", "GameHouse", "GAMEHOUSE",
                "gamehouse2017", "GameHouse2017",
                "c0qmp9w48rmualzskdfjvn091287n5crp0um1",
                "p920c8u4enoq)(&b(*&%v334&^",
                "xyht25nHg4f52sLo0mw4Ji84ki3qi",
            };

            foreach (var pwd in commonPasswords)
            {
                if (_cts.Token.IsCancellationRequested || _passwordFound) break;
                await TestAndVerifyAsync(pwd);
            }
            if (_passwordFound) return;

            Log("");
            Log("[Phase 2] Progressive brute force (smart order)...");
            Log("Strategy: For each length, try simpler charsets first");

            // Progressive attack: for each length, try simpler charsets first
            // This is smarter than doing all lengths of one charset
            for (int len = 1; len <= MaxLength && !_passwordFound && !_cts.Token.IsCancellationRequested; len++)
            {
                Log($"");
                Log($"=== Length {len} ===");

                // 1. Numbers only (fastest - only 10 chars)
                if (!_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    long numCombos = (long)Math.Pow(DIGITS.Length, len);
                    Log($"[{len}a] Digits only: {numCombos:N0} combinations");
                    await BruteForceLengthAsync(DIGITS, len, numCombos);
                }

                // 2. Lowercase only (26 chars)
                if (!_passwordFound && !_cts.Token.IsCancellationRequested && len <= 6)
                {
                    long lowerCombos = (long)Math.Pow(LOWER.Length, len);
                    Log($"[{len}b] Lowercase only: {lowerCombos:N0} combinations");
                    await BruteForceLengthAsync(LOWER, len, lowerCombos);
                }

                // 3. Uppercase only (26 chars) - less common but check short ones
                if (!_passwordFound && !_cts.Token.IsCancellationRequested && len <= 4)
                {
                    long upperCombos = (long)Math.Pow(UPPER.Length, len);
                    Log($"[{len}c] Uppercase only: {upperCombos:N0} combinations");
                    await BruteForceLengthAsync(UPPER, len, upperCombos);
                }

                // 4. Mixed case letters (52 chars) - only for short passwords
                if (!_passwordFound && !_cts.Token.IsCancellationRequested && len <= 4)
                {
                    long mixedCombos = (long)Math.Pow((LOWER + UPPER).Length, len);
                    Log($"[{len}d] Mixed case: {mixedCombos:N0} combinations");
                    await BruteForceLengthAsync(LOWER + UPPER, len, mixedCombos);
                }

                // 5. Alphanumeric (62 chars) - only for short passwords
                if (!_passwordFound && !_cts.Token.IsCancellationRequested && len <= 4)
                {
                    long alphaCombos = (long)Math.Pow((LOWER + UPPER + DIGITS).Length, len);
                    Log($"[{len}e] Alphanumeric: {alphaCombos:N0} combinations");
                    await BruteForceLengthAsync(LOWER + UPPER + DIGITS, len, alphaCombos);
                }

                // 6. With special chars (76 chars) - only for very short passwords
                if (!_passwordFound && !_cts.Token.IsCancellationRequested && len <= 3)
                {
                    long allCombos = (long)Math.Pow((LOWER + UPPER + DIGITS + SPECIAL).Length, len);
                    Log($"[{len}f] All chars: {allCombos:N0} combinations");
                    await BruteForceLengthAsync(LOWER + UPPER + DIGITS + SPECIAL, len, allCombos);
                }
            }

            if (!_passwordFound)
            {
                Log("");
                Log("[Phase 3] Extended lowercase search (7-8 chars)...");
                for (int len = 7; len <= 8 && !_passwordFound && !_cts.Token.IsCancellationRequested; len++)
                {
                    long combos = (long)Math.Pow(LOWER.Length, len);
                    Log($"Lowercase {len} chars: {combos:N0} combinations");
                    await BruteForceLengthAsync(LOWER, len, combos);
                }
            }
        }

        /// <summary>
        /// Progressive brute force - ไล่จาก charset ง่ายไปยาก สำหรับแต่ละความยาว
        /// เช่น ถ้าเลือก Alphanumeric จะไล่: digits -> lowercase -> uppercase -> mixed -> alphanumeric
        /// ถ้า IsHybridMode = true (CPU+GPU), CPU จะทำเฉพาะ Digits เท่านั้น
        /// </summary>
        private async Task ProgressiveBruteForceAsync(string fullCharset)
        {
            const string DIGITS = "0123456789";
            const string LOWER = "abcdefghijklmnopqrstuvwxyz";
            const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string SPECIAL = "!@#$%^&*()_+-=";

            // Determine which charsets are included in the full charset
            bool hasDigits = fullCharset.Any(c => DIGITS.Contains(c));
            bool hasLower = fullCharset.Any(c => LOWER.Contains(c));
            bool hasUpper = fullCharset.Any(c => UPPER.Contains(c));
            bool hasSpecial = fullCharset.Any(c => SPECIAL.Contains(c));

            Log("");
            if (IsHybridMode)
            {
                Log("=== HYBRID MODE: CPU handles DIGITS ONLY ===");
                Log("GPU will handle all other patterns (lowercase, uppercase, mixed, etc.)");
            }
            else
            {
                Log("Progressive brute force strategy:");
                Log("For each length, try simpler charsets first");
            }

            for (int len = MinLength; len <= MaxLength && !_passwordFound && !_cts.Token.IsCancellationRequested; len++)
            {
                Log($"");
                Log($"=== Length {len} ===");

                // 1. Digits only (if included) - CPU ALWAYS does this in Hybrid mode
                if (hasDigits && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    string charset = new string(fullCharset.Where(c => DIGITS.Contains(c)).ToArray());
                    if (charset.Length > 0)
                    {
                        long combos = (long)Math.Pow(charset.Length, len);
                        string patternName = $"Digits {len}-char";
                        SetCurrentPattern(patternName);
                        Log($"[CPU] {patternName}: {combos:N0} combinations");
                        await BruteForceLengthAsync(charset, len, combos);
                    }
                }

                // In Hybrid mode, CPU ONLY does digits - skip other patterns (GPU handles them)
                if (IsHybridMode)
                {
                    continue; // Skip to next length, GPU will handle other patterns
                }

                // 2. Lowercase only (if included)
                if (hasLower && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    string charset = new string(fullCharset.Where(c => LOWER.Contains(c)).ToArray());
                    if (charset.Length > 0)
                    {
                        long combos = (long)Math.Pow(charset.Length, len);
                        string patternName = $"Lowercase {len}-char";
                        SetCurrentPattern(patternName);
                        Log($"[CPU] {patternName}: {combos:N0} combinations");
                        await BruteForceLengthAsync(charset, len, combos);
                    }
                }

                // 3. Uppercase only (if included)
                if (hasUpper && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    string charset = new string(fullCharset.Where(c => UPPER.Contains(c)).ToArray());
                    if (charset.Length > 0)
                    {
                        long combos = (long)Math.Pow(charset.Length, len);
                        string patternName = $"Uppercase {len}-char";
                        SetCurrentPattern(patternName);
                        Log($"[CPU] {patternName}: {combos:N0} combinations");
                        await BruteForceLengthAsync(charset, len, combos);
                    }
                }

                // 4. Letters mixed (lower + upper, if both included)
                if (hasLower && hasUpper && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    string charset = new string(fullCharset.Where(c => LOWER.Contains(c) || UPPER.Contains(c)).ToArray());
                    if (charset.Length > 0)
                    {
                        long combos = (long)Math.Pow(charset.Length, len);
                        string patternName = $"Mixed {len}-char";
                        SetCurrentPattern(patternName);
                        Log($"[CPU] {patternName}: {combos:N0} combinations");
                        await BruteForceLengthAsync(charset, len, combos);
                    }
                }

                // 5. Alphanumeric (letters + digits, if all included)
                if ((hasLower || hasUpper) && hasDigits && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    string charset = new string(fullCharset.Where(c => LOWER.Contains(c) || UPPER.Contains(c) || DIGITS.Contains(c)).ToArray());
                    if (charset.Length > 0)
                    {
                        long combos = (long)Math.Pow(charset.Length, len);
                        string patternName = $"Alphanumeric {len}-char";
                        SetCurrentPattern(patternName);
                        Log($"[CPU] {patternName}: {combos:N0} combinations");
                        await BruteForceLengthAsync(charset, len, combos);
                    }
                }

                // 6. Full charset (including special if any)
                if (hasSpecial && !_passwordFound && !_cts.Token.IsCancellationRequested)
                {
                    long combos = (long)Math.Pow(fullCharset.Length, len);
                    string patternName = $"Full {len}-char";
                    SetCurrentPattern(patternName);
                    Log($"[CPU] {patternName}: {combos:N0} combinations");
                    await BruteForceLengthAsync(fullCharset, len, combos);
                }
            }

            SetCurrentPattern("Completed");
        }

        /// <summary>
        /// Set current pattern and notify UI
        /// </summary>
        private void SetCurrentPattern(string pattern)
        {
            CurrentPattern = pattern;
            OnPatternChanged?.Invoke(pattern);
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

                            // For length 1, each thread handles one character, so break after testing
                            if (length == 1) break;

                            // Increment from rightmost position (but not position 0 which is fixed per thread)
                            int pos = length - 1;
                            while (pos >= 1)
                            {
                                indices[pos]++;
                                if (indices[pos] < charsetLen) break;
                                indices[pos] = 0;
                                pos--;
                            }

                            // If we've exhausted all combinations for this first character, exit
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

        // Flag to track if 7-Zip availability was already checked and warned
        private bool _7zipWarningShown = false;

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

            // For WinZip AES - need 7-Zip for verification
            if (IsWinZipAES)
            {
                // Check if 7-Zip is available before attempting verification
                string sevenZipPath = Find7ZipPath();

                if (sevenZipPath == null)
                {
                    // 7-Zip not found - can't verify WinZip AES passwords
                    if (!_7zipWarningShown)
                    {
                        _7zipWarningShown = true;
                        Log("");
                        Log("=================================================");
                        Log("ERROR: Cannot crack WinZip AES without 7-Zip!");
                        Log("=================================================");
                        Log("WinZip AES encryption requires 7-Zip for password verification.");
                        Log("");
                        Log("Solutions:");
                        Log("1. Install 7-Zip from: https://www.7-zip.org/");
                        Log("2. Or use GPU mode (Hashcat) - much faster for AES");
                        Log("");
                    }
                    return false; // Skip this password - can't verify without 7-Zip
                }

                // Log first time 7-Zip is found
                if (_totalAttempts == 1)
                {
                    Log($"✓ Using 7-Zip for AES verification: {sevenZipPath}");
                }

                // 7-Zip available - return true to verify with 7-Zip
                return true;
            }

            // For 7-Zip archives - need 7-Zip for verification
            if (Is7zArchive)
            {
                // Check if 7-Zip is available
                string sevenZipPath = Find7ZipPath();

                if (sevenZipPath == null)
                {
                    if (!_7zipWarningShown)
                    {
                        _7zipWarningShown = true;
                        Log("");
                        Log("=================================================");
                        Log("ERROR: Cannot crack 7-Zip archives without 7-Zip!");
                        Log("=================================================");
                        Log("7-Zip encryption requires 7-Zip for password verification.");
                        Log("");
                        Log("Solutions:");
                        Log("1. Install 7-Zip from: https://www.7-zip.org/");
                        Log("2. Or use GPU mode (Hashcat) - much faster");
                        Log("");
                    }
                    return false;
                }

                return true;
            }

            // PKZIP (ZipCrypto) - ใช้ fast header check
            if (_encryptedHeader == null || _encryptedHeader.Length < 12)
            {
                // ถ้าไม่มี header ให้ไป verify ตรงๆ
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
            string ext = Path.GetExtension(ZipFilePath).ToLowerInvariant();
            bool isZip = ext == ".zip" || IsWinZipAES;

            // For ZIP files, try 7-Zip first (better for AES)
            if (isZip)
            {
                var result = VerifyWith7Zip(password);
                if (result.HasValue) return result.Value;
            }

            // Try WinRAR/UnRAR for RAR files or as fallback
            return VerifyWithWinRAR(password);
        }

        // Cached 7-Zip path to avoid repeated searches
        private static string _cached7ZipPath = null;
        private static bool _7zipSearched = false;

        /// <summary>
        /// Find 7-Zip executable path (cached)
        /// </summary>
        private string Find7ZipPath()
        {
            if (_7zipSearched)
            {
                return _cached7ZipPath;
            }

            // Try to find 7-Zip in common locations
            string[] sevenZipPaths = {
                @"C:\Program Files\7-Zip\7z.exe",
                @"C:\Program Files (x86)\7-Zip\7z.exe",
                @"D:\Program Files\7-Zip\7z.exe",
                @"D:\Program Files (x86)\7-Zip\7z.exe",
                @"E:\Program Files\7-Zip\7z.exe",
                Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\7-Zip\7z.exe"),
                Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\7-Zip\7z.exe"),
                Environment.ExpandEnvironmentVariables(@"%LocalAppData%\Programs\7-Zip\7z.exe"),
            };

            string sevenZipPath = null;
            foreach (var path in sevenZipPaths)
            {
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    sevenZipPath = path;
                    break;
                }
            }

            _7zipSearched = true;
            _cached7ZipPath = sevenZipPath;

            return sevenZipPath;
        }

        private bool? VerifyWith7Zip(string password)
        {
            string sevenZipPath = Find7ZipPath();

            if (sevenZipPath == null)
            {
                return null; // Not found, try other methods
            }

            return TryExtractWith7Zip(sevenZipPath, password);
        }

        private bool? TryExtractWith7Zip(string sevenZipPath, string password)
        {
            try
            {
                // Use 't' (test) command instead of 'x' (extract) - much faster!
                // 7z t -p<password> archive.zip
                var args = $"t -p\"{password}\" \"{ZipFilePath}\"";

                var psi = new ProcessStartInfo
                {
                    FileName = sevenZipPath,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    Log($"ERROR: Failed to start 7-Zip process");
                    return null;
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                if (!process.WaitForExit(10000)) // 10 second timeout
                {
                    try { process.Kill(); } catch { }
                    return false;
                }

                // Exit code 0 = success (password correct)
                // Exit code 2 = wrong password or CRC error
                int exitCode = process.ExitCode;

                // Check for "Everything is Ok" in output to confirm success
                bool success = exitCode == 0 && output.Contains("Everything is Ok");

                // Debug: Log when password is found
                if (success)
                {
                    Log($"✓ 7-Zip verified password: {password}");
                }

                return success;
            }
            catch
            {
                return null; // Error, try other methods
            }
        }

        private bool VerifyWithWinRAR(string password)
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
