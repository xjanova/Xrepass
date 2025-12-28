using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ZipCrackerUI
{
    /// <summary>
    /// ตรวจสอบและจัดการ hash format ของ archive ประเภทต่างๆ
    /// รองรับ: ZIP (PKZIP, ZipCrypto, WinZip AES), RAR3, RAR5, 7z, TAR, GZ
    /// พร้อม Deep Scan และ Timeout Protection
    /// </summary>
    public class HashFormatDetector
    {
        // Tool paths - set from MainWindow
        private static string _7z2johnPath;
        private static string _perlPath;
        private static string _rar2johnPath;
        private static string _pythonPath;

        // Scan settings - ลดเวลาและขนาดเพื่อไม่ให้ UI ค้าง
        private const int DEFAULT_SCAN_TIMEOUT_MS = 5000; // 5 วินาที (ลดจาก 30 วินาที)
        private const int MAX_SCAN_SIZE_MB = 50; // ไฟล์ใหญ่กว่านี้สแกนแค่ส่วนแรก
        private const int DEEP_SCAN_CHUNK_SIZE = 256 * 1024; // 256KB per chunk (เช็ค cancellation บ่อยขึ้น)

        /// <summary>
        /// Set path to 7z2john tool
        /// </summary>
        public static void Set7z2JohnPath(string path)
        {
            _7z2johnPath = path;
        }

        /// <summary>
        /// Set path to Perl executable
        /// </summary>
        public static void SetPerlPath(string path)
        {
            _perlPath = path;
        }

        /// <summary>
        /// Set path to rar2john tool
        /// </summary>
        public static void SetRar2JohnPath(string path)
        {
            _rar2johnPath = path;
        }

        /// <summary>
        /// Set path to Python executable
        /// </summary>
        public static void SetPythonPath(string path)
        {
            _pythonPath = path;
        }

        /// <summary>
        /// Get current 7z2john path
        /// </summary>
        public static string Get7z2JohnPath() => _7z2johnPath;

        public enum HashType
        {
            Unknown,
            PKZIP_Traditional,  // Mode 17200-17230
            WinZip_AES,         // Mode 13600
            ZIP2_John,          // Mode 13600 (old format)
            RAR3,               // Mode 12500 (old RAR)
            RAR5,               // Mode 13000
            SevenZip,           // Mode 11600
            TAR_GZ,             // TAR with GZIP
            TAR_BZ2,            // TAR with BZIP2
            TAR_XZ,             // TAR with XZ
            GZ,                 // GZIP alone
            BZ2,                // BZIP2 alone
            XZ                  // XZ alone
        }

        public class HashInfo
        {
            public HashType Type { get; set; }
            public int HashcatMode { get; set; }
            public string Hash { get; set; }
            public string FileName { get; set; }
            public int CompressionType { get; set; }
            public bool IsValid { get; set; }
            public string ErrorMessage { get; set; }
        }

        /// <summary>
        /// ตรวจสอบและสร้าง hash ตามประเภทของไฟล์ (Async version - ใช้แทนเพื่อไม่ให้ UI ค้าง)
        /// รองรับ: ZIP (รวม SFX .exe), RAR, 7z, TAR, GZ, BZ2, XZ
        /// พร้อม Timeout และ Deep Scan
        /// </summary>
        public static async System.Threading.Tasks.Task<HashInfo> ExtractHashAsync(string filePath, int timeoutMs = DEFAULT_SCAN_TIMEOUT_MS)
        {
            if (!File.Exists(filePath))
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = "File not found"
                };
            }

            var cancellation = new System.Threading.CancellationTokenSource(timeoutMs);

            try
            {
                return await System.Threading.Tasks.Task.Run(() => ExtractHashInternal(filePath, cancellation.Token), cancellation.Token);
            }
            catch (System.Threading.Tasks.TaskCanceledException)
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = $"Detection timeout ({timeoutMs / 1000}s) - File may be corrupted or too large"
                };
            }
            catch (Exception ex)
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = $"Error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// ตรวจสอบและสร้าง hash ตามประเภทของไฟล์ (Sync version - ใช้เฉพาะกรณีจำเป็น)
        /// รองรับ: ZIP (รวม SFX .exe), RAR, 7z, TAR, GZ, BZ2, XZ
        /// พร้อม Timeout และ Deep Scan
        /// WARNING: This blocks the calling thread. Use ExtractHashAsync() instead to prevent UI freezing.
        /// </summary>
        public static HashInfo ExtractHash(string filePath, int timeoutMs = DEFAULT_SCAN_TIMEOUT_MS)
        {
            // Use async version and wait for result
            return ExtractHashAsync(filePath, timeoutMs).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Internal method with cancellation token support
        /// </summary>
        private static HashInfo ExtractHashInternal(string filePath, System.Threading.CancellationToken token)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var br = new BinaryReader(fs);

                if (fs.Length < 4)
                {
                    return new HashInfo
                    {
                        IsValid = false,
                        ErrorMessage = "File too small to be an archive"
                    };
                }

                long fileSizeMB = fs.Length / (1024 * 1024);
                bool useDeepScan = fileSizeMB > MAX_SCAN_SIZE_MB;

                // อ่าน signature (first 4 bytes)
                var sig = br.ReadUInt32();
                fs.Position = 0;

                // Check cancellation
                token.ThrowIfCancellationRequested();

                // Quick check - known signatures
                HashInfo result = QuickSignatureCheck(sig, br, filePath, token);
                if (result != null)
                    return result;

                // Deep scan - scan entire file for archive signatures
                return DeepScanForArchive(br, filePath, useDeepScan, token);
            }
            catch (System.OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = $"Error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Quick check for known signatures at file start
        /// </summary>
        private static HashInfo QuickSignatureCheck(uint sig, BinaryReader br, string filePath, System.Threading.CancellationToken token)
        {
            // ZIP signature (PK\x03\x04 = 0x04034b50)
            if (sig == 0x04034b50)
                return ExtractZipHash(br, filePath);

            // RAR signature (Rar! = 0x21726152)
            if (sig == 0x21726152)
                return ExtractRarHash(br, filePath);

            // 7z signature (0xAFBC7A37)
            if (sig == 0xAFBC7A37)
                return Extract7zHash(br, filePath);

            // GZIP signature (0x1F8B)
            if ((sig & 0xFFFF) == 0x8B1F)
                return DetectCompressedTar(br, filePath, "GZ");

            // BZIP2 signature (BZ)
            if ((sig & 0xFFFF) == 0x5A42)
                return DetectCompressedTar(br, filePath, "BZ2");

            // XZ signature (0xFD377A58)
            if ((sig & 0xFFFFFFFF) == 0xFD377A58)
                return DetectCompressedTar(br, filePath, "XZ");

            // TAR signature (ustar at offset 257)
            if (CheckTarSignature(br))
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = "TAR archive detected (no password protection)"
                };

            // MZ signature (EXE/DLL = "MZ")
            if ((sig & 0xFFFF) == 0x5A4D)
                return ExtractZipFromSFX(br, filePath);

            return null; // Not found - need deep scan
        }

        /// <summary>
        /// Deep scan - ค้นหา signature ทั่วทั้งไฟล์ (จำกัดขนาดเพื่อไม่ให้ค้าง)
        /// </summary>
        private static HashInfo DeepScanForArchive(BinaryReader br, string filePath, bool useChunked, System.Threading.CancellationToken token)
        {
            long fileSize = br.BaseStream.Length;
            // ลดขนาดการสแกนลง - สำหรับไฟล์ใหญ่สแกนแค่ 5MB แรก
            long maxScan = useChunked ? Math.Min(fileSize, 5 * 1024 * 1024) : Math.Min(fileSize, 10 * 1024 * 1024);

            br.BaseStream.Position = 0;

            // สแกนทีละ 4 bytes แต่เช็ค cancellation ทุก 256 bytes (เร็วขึ้น)
            for (long pos = 0; pos < maxScan - 4; pos += 4)
            {
                // Check every 256 bytes (บ่อยขึ้นเพื่อ responsive)
                if (pos % 256 == 0)
                    token.ThrowIfCancellationRequested();

                br.BaseStream.Position = pos;
                uint sig = br.ReadUInt32();

                // ZIP
                if (sig == 0x04034b50)
                {
                    br.BaseStream.Position = pos;
                    return ExtractZipHash(br, filePath);
                }

                // RAR
                if (sig == 0x21726152)
                {
                    br.BaseStream.Position = pos;
                    return ExtractRarHash(br, filePath);
                }

                // 7z
                if (sig == 0xAFBC7A37)
                {
                    br.BaseStream.Position = pos;
                    return Extract7zHash(br, filePath);
                }
            }

            return new HashInfo
            {
                IsValid = false,
                ErrorMessage = $"Unknown or unsupported archive format.\nScanned: {maxScan / 1024:N0} KB of {fileSize / 1024:N0} KB\n\nSupported: ZIP, RAR, 7-Zip, TAR.GZ"
            };
        }

        /// <summary>
        /// ตรวจสอบ TAR signature
        /// </summary>
        private static bool CheckTarSignature(BinaryReader br)
        {
            try
            {
                if (br.BaseStream.Length < 512)
                    return false;

                br.BaseStream.Position = 257;
                var magic = Encoding.ASCII.GetString(br.ReadBytes(6));
                return magic.StartsWith("ustar");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// ตรวจสอบ TAR ที่ถูกบีบอัด (tar.gz, tar.bz2, tar.xz)
        /// </summary>
        private static HashInfo DetectCompressedTar(BinaryReader br, string filePath, string compType)
        {
            return new HashInfo
            {
                IsValid = false,
                ErrorMessage = $"{compType} archive detected - Compressed TAR archives typically have no password protection. Try extracting first."
            };
        }

        /// <summary>
        /// สร้าง hash สำหรับ ZIP (ตรวจสอบ PKZIP, WinZip AES)
        /// </summary>
        private static HashInfo ExtractZipHash(BinaryReader br, string filePath)
        {
            while (br.BaseStream.Position < br.BaseStream.Length - 30)
            {
                long entryStart = br.BaseStream.Position;
                var sig = br.ReadUInt32();

                if (sig != 0x04034b50) // PK\x03\x04
                {
                    br.BaseStream.Position = entryStart + 1;
                    continue;
                }

                var version = br.ReadUInt16();
                var flags = br.ReadUInt16();
                var compression = br.ReadUInt16();
                var modTime = br.ReadUInt16();
                var modDate = br.ReadUInt16();
                var crc32 = br.ReadUInt32();
                var compSize = br.ReadUInt32();
                var uncompSize = br.ReadUInt32();
                var fnLen = br.ReadUInt16();
                var extraLen = br.ReadUInt16();

                var fileName = Encoding.UTF8.GetString(br.ReadBytes(fnLen));

                // ตรวจสอบ extra field สำหรับ WinZip AES
                bool isWinZipAES = false;
                int aesStrength = 0;

                if (extraLen > 0)
                {
                    long extraStart = br.BaseStream.Position;
                    var extraData = br.ReadBytes(extraLen);

                    // ตรวจสอบ AES extra field (0x9901)
                    // WinZip AES Extra Field structure:
                    // - 2 bytes: Header ID (0x9901 = bytes 01 99 in little-endian)
                    // - 2 bytes: Data size (usually 7)
                    // - 2 bytes: AES version (0x0001 or 0x0002)
                    // - 2 bytes: Vendor ID ("AE" = 0x4145)
                    // - 1 byte: AES strength (1=128, 2=192, 3=256) <- offset +8 from header ID
                    // - 2 bytes: Actual compression method
                    for (int i = 0; i < extraData.Length - 8; i++)
                    {
                        if (extraData[i] == 0x01 && extraData[i + 1] == 0x99)
                        {
                            isWinZipAES = true;
                            // AES strength is at offset i+8 (after header ID, size, version, vendor ID)
                            if (i + 8 < extraData.Length)
                                aesStrength = extraData[i + 8];
                            break;
                        }
                    }
                }

                long dataOffset = br.BaseStream.Position;

                // ถ้ามี encryption flag
                if ((flags & 1) == 1 && compSize > 0)
                {
                    if (isWinZipAES)
                    {
                        // WinZip AES
                        return ExtractWinZipAESHash(br, fileName, compression, aesStrength, dataOffset, (int)compSize, uncompSize);
                    }
                    else
                    {
                        // Traditional PKZIP (ZipCrypto)
                        return ExtractPKZIPHash(br, fileName, compression, crc32, modTime, dataOffset, (int)compSize);
                    }
                }

                if (compSize > 0)
                    br.BaseStream.Position += compSize;
            }

            return new HashInfo
            {
                IsValid = false,
                ErrorMessage = "No encrypted files found in ZIP"
            };
        }

        /// <summary>
        /// สร้าง hash สำหรับ PKZIP Traditional (ZipCrypto)
        /// </summary>
        private static HashInfo ExtractPKZIPHash(BinaryReader br, string fileName, int compression,
            uint crc32, ushort modTime, long dataOffset, int compSize)
        {
            // อ่าน encrypted header (12 bytes)
            var encData = br.ReadBytes(Math.Min(12, compSize));

            byte crcCheck = (byte)((crc32 >> 24) & 0xFF);
            byte timeCheck = (byte)((modTime >> 8) & 0xFF);

            // สร้าง hash ในรูปแบบ $pkzip2$
            var sb = new StringBuilder();
            sb.Append("$pkzip2$");
            sb.Append("*");
            sb.Append($"{compression}*");  // Compression type
            sb.Append("0*");  // Checksum type (0 = CRC)
            sb.Append($"{crcCheck:x2}*");  // CRC check byte
            sb.Append($"{timeCheck:x2}*");  // Time check byte

            // Encrypted header
            foreach (var b in encData)
                sb.Append(b.ToString("x2"));

            sb.Append("*$/pkzip2$");

            // เลือก Hashcat mode ตาม compression type
            int mode = compression switch
            {
                0 => 17210,   // Store
                8 => 17200,   // Deflate
                9 => 17220,   // Deflate64
                14 => 17225,  // LZMA
                2 or 3 or 4 or 5 => 17230,  // Reduce
                _ => 17200    // Default
            };

            return new HashInfo
            {
                Type = HashType.PKZIP_Traditional,
                HashcatMode = mode,
                Hash = sb.ToString(),
                FileName = fileName,
                CompressionType = compression,
                IsValid = true
            };
        }

        /// <summary>
        /// สร้าง hash สำหรับ WinZip AES (Mode 13600)
        /// Hashcat format: $zip2$*type*mode*magic*salt*verify_bytes*data_len*data*auth*$/zip2$
        /// Example: $zip2$*0*3*0*e3222d3b65b5a2785b192d31e39ff9de*1320*e*19648c3e063c82a9ad3ef08ed833*3135c79ecb86cd6f48fc*$/zip2$
        /// </summary>
        private static HashInfo ExtractWinZipAESHash(BinaryReader br, string fileName, int compression,
            int aesStrength, long dataOffset, int compSize, uint uncompSize)
        {
            // WinZip AES structure:
            // - Salt (8/12/16 bytes depending on strength 1/2/3)
            // - Password verification (2 bytes)
            // - Encrypted data (compSize - salt - 2 - 10)
            // - Authentication code (10 bytes)

            // Determine salt size: AES-128=8, AES-192=12, AES-256=16
            int saltSize = aesStrength switch
            {
                1 => 8,   // AES-128
                2 => 12,  // AES-192
                3 => 16,  // AES-256
                _ => 16   // Default to AES-256
            };

            int authCodeSize = 10;
            int pvSize = 2; // Password verification
            int encryptedDataSize = compSize - saltSize - pvSize - authCodeSize;

            if (encryptedDataSize < 1)
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = "Invalid WinZip AES data: file too small"
                };
            }

            // Read all data
            var allData = br.ReadBytes(compSize);
            if (allData.Length < compSize)
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = "Could not read enough data from archive"
                };
            }

            // Extract components
            var salt = new byte[saltSize];
            var pv = new byte[pvSize];
            var authCode = new byte[authCodeSize];

            Array.Copy(allData, 0, salt, 0, saltSize);
            Array.Copy(allData, saltSize, pv, 0, pvSize);
            Array.Copy(allData, allData.Length - authCodeSize, authCode, 0, authCodeSize);

            // Extract encrypted data (between pv and authCode)
            int encryptedDataStart = saltSize + pvSize;
            int encryptedDataLen = allData.Length - saltSize - pvSize - authCodeSize;
            var encryptedData = new byte[encryptedDataLen > 0 ? encryptedDataLen : 0];
            if (encryptedDataLen > 0)
            {
                Array.Copy(allData, encryptedDataStart, encryptedData, 0, encryptedDataLen);
            }

            // Build hash string in format for Hashcat mode 13600:
            // $zip2$*type*mode*magic*salt*verify_bytes*compress_length*data*auth_tag*$/zip2$
            // Example from hashcat: $zip2$*0*3*0*e3222d3b65b5a2785b192d31e39ff9de*1320*e*19648c3e063c82a9ad3ef08ed833*3135c79ecb86cd6f48fc*$/zip2$
            // Where:
            // - type = 0 (file) or 1 (directory)
            // - mode = 1/2/3 for AES strength (128/192/256)
            // - magic = 0 (reserved)
            // - salt = hex encoded salt (16/24/32 hex chars for mode 1/2/3)
            // - verify_bytes = password verification (4 hex chars = 2 bytes)
            // - compress_length = hex length of encrypted data
            // - data = hex encoded encrypted data (REQUIRED for cracking!)
            // - auth_tag = hex encoded HMAC (20 hex chars = 10 bytes)

            var sb = new StringBuilder();
            sb.Append("$zip2$*");
            sb.Append("0*");                    // type (0=file)
            sb.Append($"{aesStrength}*");       // mode (1=128, 2=192, 3=256)
            sb.Append("0*");                    // magic

            // Salt (hex)
            foreach (var b in salt)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Password verification bytes (hex) - 2 bytes = 4 hex chars
            foreach (var b in pv)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Compressed length in hex (required!)
            sb.Append($"{encryptedDataLen:x}*");

            // Encrypted data (hex) - REQUIRED for password cracking!
            foreach (var b in encryptedData)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Authentication code (hex) - 10 bytes HMAC
            foreach (var b in authCode)
                sb.Append(b.ToString("x2"));

            // End marker - asterisk before $/zip2$ is REQUIRED
            sb.Append("*$/zip2$");

            return new HashInfo
            {
                Type = HashType.WinZip_AES,
                HashcatMode = 13600,
                Hash = sb.ToString(),
                FileName = fileName,
                CompressionType = compression,
                IsValid = true
            };
        }

        /// <summary>
        /// สร้าง hash สำหรับ RAR (Mode 13000 for RAR5, 12500 for RAR3)
        /// RAR5 format: $rar5$*salt*iv*data*iv2*checksum*
        /// RAR3 format: $RAR3$*type*hex_encoded_salt*hex_encoded_data*
        /// </summary>
        private static HashInfo ExtractRarHash(BinaryReader br, string filePath)
        {
            // ตรวจสอบ RAR version จาก signature
            br.BaseStream.Position = 0;
            var sig = br.ReadBytes(8);

            // RAR5: Rar!\x1a\x07\x01\x00
            bool isRar5 = sig.Length >= 8 && sig[6] == 0x01 && sig[7] == 0x00;

            // Try rar2john first - much more reliable than manual parsing
            string hash = TryRunRar2John(filePath);
            if (!string.IsNullOrEmpty(hash))
            {
                // Successfully extracted hash with rar2john
                // Determine hash type from the hash string
                int hashcatMode = hash.Contains("$rar5$") ? 13000 : 12500;
                var hashType = hash.Contains("$rar5$") ? HashType.RAR5 : HashType.RAR3;

                return new HashInfo
                {
                    Type = hashType,
                    HashcatMode = hashcatMode,
                    Hash = hash,
                    FileName = Path.GetFileName(filePath),
                    IsValid = true
                };
            }

            // rar2john failed - fall back to manual parsing
            if (isRar5)
            {
                // RAR5 - Need to extract hash
                // RAR5 uses a more complex format, but we can use rar2john format
                // For now, we try to extract basic info or fall back to external tool

                return ExtractRar5Hash(br, filePath);
            }
            else
            {
                // RAR3 - Mode 12500 (hp) or 23800 (p)
                return ExtractRar3Hash(br, filePath);
            }
        }

        /// <summary>
        /// Extract RAR5 hash (Mode 13000)
        /// </summary>
        private static HashInfo ExtractRar5Hash(BinaryReader br, string filePath)
        {
            // RAR5 format is complex - need to parse headers
            // For now, return info that tells the app to use rar2john or similar
            // RAR5 uses PBKDF2-HMAC-SHA256

            br.BaseStream.Position = 7; // Skip signature

            try
            {
                // Read main archive header
                // RAR5 uses variable-length header format
                // We need to find the encryption record

                // Skip to find encrypted file headers
                while (br.BaseStream.Position < br.BaseStream.Length - 20)
                {
                    long headerPos = br.BaseStream.Position;

                    // Read header CRC (4 bytes)
                    uint headerCrc = br.ReadUInt32();

                    // Read header size (vint)
                    ulong headerSize = ReadVInt(br);
                    if (headerSize == 0 || headerSize > 0xFFFFFF) break;

                    // Read header type (vint)
                    ulong headerType = ReadVInt(br);

                    // Type 4 = Encryption header
                    if (headerType == 4)
                    {
                        // Found encryption header - extract encryption params
                        ulong flags = ReadVInt(br);
                        ulong version = ReadVInt(br);
                        ulong encFlags = ReadVInt(br);
                        ulong kdfCount = ReadVInt(br);

                        // Read salt (16 bytes)
                        var salt = br.ReadBytes(16);

                        // Read check value (12 bytes for password check)
                        var checkValue = br.ReadBytes(12);

                        // Build RAR5 hash
                        // Format: $rar5$16$salt$15$checkvalue$8$0
                        var sb = new StringBuilder();
                        sb.Append("$rar5$16$");

                        foreach (var b in salt)
                            sb.Append(b.ToString("x2"));

                        sb.Append("$15$");

                        foreach (var b in checkValue)
                            sb.Append(b.ToString("x2"));

                        sb.Append($"$8${kdfCount}");

                        return new HashInfo
                        {
                            Type = HashType.RAR5,
                            HashcatMode = 13000,
                            Hash = sb.ToString(),
                            FileName = filePath,
                            IsValid = true
                        };
                    }

                    // Skip to next header
                    br.BaseStream.Position = headerPos + (long)headerSize + 4;
                }
            }
            catch
            {
                // Fall through to return basic info
            }

            // Could not extract - suggest using rar2john
            string errorMsg = "RAR5 detected - rar2john.py tool required for hash extraction";

            if (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath))
            {
                // Tool exists but failed to run - likely missing Python
                errorMsg = "RAR5 detected - Python interpreter required to run rar2john.py\n" +
                           "Download Python Portable from Settings.";
            }

            return new HashInfo
            {
                Type = HashType.RAR5,
                HashcatMode = 13000,
                Hash = null,
                FileName = filePath,
                IsValid = false,
                ErrorMessage = errorMsg
            };
        }

        /// <summary>
        /// Extract RAR3 hash (Mode 12500)
        /// </summary>
        private static HashInfo ExtractRar3Hash(BinaryReader br, string filePath)
        {
            // RAR3 format - need to find encrypted file header
            br.BaseStream.Position = 7; // Skip "Rar!\x1a\x07\x00"

            try
            {
                while (br.BaseStream.Position < br.BaseStream.Length - 20)
                {
                    long headerPos = br.BaseStream.Position;

                    // RAR3 header structure:
                    // 2 bytes: HEAD_CRC
                    // 1 byte: HEAD_TYPE
                    // 2 bytes: HEAD_FLAGS
                    // 2 bytes: HEAD_SIZE

                    ushort headCrc = br.ReadUInt16();
                    byte headType = br.ReadByte();
                    ushort headFlags = br.ReadUInt16();
                    ushort headSize = br.ReadUInt16();

                    if (headSize < 7) break;

                    // Type 0x74 = FILE_HEAD
                    if (headType == 0x74)
                    {
                        // Check if encrypted (flag 0x04)
                        if ((headFlags & 0x04) != 0)
                        {
                            // Read pack size and unpack size
                            uint packSize = br.ReadUInt32();
                            uint unpSize = br.ReadUInt32();
                            byte hostOs = br.ReadByte();
                            uint fileCrc = br.ReadUInt32();
                            uint fileTime = br.ReadUInt32();
                            byte unpVer = br.ReadByte();
                            byte method = br.ReadByte();
                            ushort nameSize = br.ReadUInt16();
                            uint attr = br.ReadUInt32();

                            // Read file name
                            var nameBytes = br.ReadBytes(nameSize);

                            // Read salt if present (flag 0x100)
                            byte[] salt = null;
                            if ((headFlags & 0x100) != 0)
                            {
                                salt = br.ReadBytes(8);
                            }
                            else
                            {
                                // No salt - use zeros
                                salt = new byte[8];
                            }

                            // Read encrypted data (first 16 bytes for hash)
                            var encData = br.ReadBytes(16);

                            // Build RAR3 hash
                            // Format: $RAR3$*type*salt*encrypted_data
                            // type: 0 = -hp (encrypted headers), 1 = -p (encrypted data only)
                            int encType = (headFlags & 0x200) != 0 ? 0 : 1;

                            var sb = new StringBuilder();
                            sb.Append($"$RAR3$*{encType}*");

                            foreach (var b in salt)
                                sb.Append(b.ToString("x2"));
                            sb.Append("*");

                            foreach (var b in encData)
                                sb.Append(b.ToString("x2"));

                            return new HashInfo
                            {
                                Type = HashType.RAR3,
                                HashcatMode = 12500,
                                Hash = sb.ToString(),
                                FileName = filePath,
                                IsValid = true
                            };
                        }
                    }

                    // Skip to next header
                    br.BaseStream.Position = headerPos + headSize;

                    // If file header, skip data too
                    if (headType == 0x74)
                    {
                        long packSize = br.ReadUInt32();
                        br.BaseStream.Position = headerPos + headSize + packSize;
                    }
                }
            }
            catch
            {
                // Fall through
            }

            string errorMsg = "RAR3 detected - rar2john.py tool required for hash extraction";

            if (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath))
            {
                // Tool exists but failed to run - likely missing Python
                errorMsg = "RAR3 detected - Python interpreter required to run rar2john.py\n" +
                           "Download Python Portable from Settings.";
            }

            return new HashInfo
            {
                Type = HashType.RAR3,
                HashcatMode = 12500,
                Hash = null,
                FileName = filePath,
                IsValid = false,
                ErrorMessage = errorMsg
            };
        }

        /// <summary>
        /// Read variable-length integer (RAR5 format)
        /// </summary>
        private static ulong ReadVInt(BinaryReader br)
        {
            ulong result = 0;
            int shift = 0;

            while (true)
            {
                byte b = br.ReadByte();
                result |= (ulong)(b & 0x7F) << shift;

                if ((b & 0x80) == 0) break;
                shift += 7;

                if (shift > 63) break; // Prevent infinite loop
            }

            return result;
        }

        /// <summary>
        /// สร้าง hash สำหรับ 7-Zip (Mode 11600)
        /// Format: $7z$0$iterations$salt_len$salt$iv_len$iv$crc$data_len$data$unp_len$
        /// </summary>
        private static HashInfo Extract7zHash(BinaryReader br, string filePath)
        {
            // 7-Zip AES encryption is complex to parse
            // Try to run 7z2john if available, otherwise return guidance

            try
            {
                br.BaseStream.Position = 0;

                // 7z signature: 37 7A BC AF 27 1C
                var sig = br.ReadBytes(6);
                if (sig[0] != 0x37 || sig[1] != 0x7A || sig[2] != 0xBC ||
                    sig[3] != 0xAF || sig[4] != 0x27 || sig[5] != 0x1C)
                {
                    return new HashInfo
                    {
                        IsValid = false,
                        ErrorMessage = "Not a valid 7-Zip file"
                    };
                }

                // Try to use 7z2john.pl from hashcat utils or John the Ripper
                string hash = TryRun7z2John(filePath);
                if (!string.IsNullOrEmpty(hash))
                {
                    return new HashInfo
                    {
                        Type = HashType.SevenZip,
                        HashcatMode = 11600,
                        Hash = hash,
                        FileName = Path.GetFileName(filePath),
                        IsValid = true
                    };
                }

                // 7z2john failed - check if it's missing tool or missing Perl
                string errorMsg = "7-Zip detected - 7z2john tool required for hash extraction";

                if (!string.IsNullOrEmpty(_7z2johnPath) && File.Exists(_7z2johnPath))
                {
                    // Tool exists but failed to run - likely missing Perl
                    errorMsg = "7-Zip detected - Perl interpreter required to run 7z2john.pl\n" +
                               "Install Strawberry Perl from: https://strawberryperl.com/";
                }

                return new HashInfo
                {
                    Type = HashType.SevenZip,
                    HashcatMode = 11600,
                    Hash = null,
                    FileName = filePath,
                    IsValid = false,
                    ErrorMessage = errorMsg
                };
            }
            catch (Exception ex)
            {
                return new HashInfo
                {
                    Type = HashType.SevenZip,
                    HashcatMode = 11600,
                    Hash = null,
                    FileName = filePath,
                    IsValid = false,
                    ErrorMessage = $"7-Zip parsing error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Try to run 7z2john to extract hash
        /// </summary>
        private static string TryRun7z2John(string filePath)
        {
            // First check the configured path from settings
            string tool7z2john = null;

            if (!string.IsNullOrEmpty(_7z2johnPath) && File.Exists(_7z2johnPath))
            {
                tool7z2john = _7z2johnPath;
            }
            else
            {
                // Try common locations for 7z2john
                string[] possiblePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "X-Repass", "tools", "7z2john.pl"),
                    @"C:\hashcat\7z2john.pl",
                    @"C:\John\run\7z2john.pl",
                    @"C:\tools\7z2john.pl",
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "7z2john.pl"),
                };

                foreach (var path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        tool7z2john = path;
                        break;
                    }
                }
            }

            if (tool7z2john == null)
                return null;

            // Check if Perl is available
            if (!IsPerlAvailable())
                return null;

            try
            {
                // Use configured Perl path if available, otherwise use "perl" (from PATH)
                string perlExe = !string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath)
                    ? _perlPath
                    : "perl";

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = perlExe,
                    Arguments = $"\"{tool7z2john}\" \"{filePath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null)
                    return null;

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    // Output format: filename:$7z$...
                    // Extract just the hash part
                    int colonIndex = output.IndexOf(':');
                    if (colonIndex >= 0 && output.Contains("$7z$"))
                    {
                        return output.Substring(colonIndex + 1).Trim();
                    }
                }
            }
            catch
            {
                // Failed to run perl
                return null;
            }

            return null;
        }

        /// <summary>
        /// Try to run rar2john to extract RAR hash
        /// </summary>
        private static string TryRunRar2John(string filePath)
        {
            // First check the configured path from settings
            string toolRar2john = null;

            if (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath))
            {
                toolRar2john = _rar2johnPath;
            }
            else
            {
                // Try common locations for rar2john
                string[] possiblePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "X-Repass", "tools", "rar2john.py"),
                    @"C:\hashcat\rar2john.py",
                    @"C:\John\run\rar2john.py",
                    @"C:\tools\rar2john.py",
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rar2john.py"),
                };

                foreach (var path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        toolRar2john = path;
                        break;
                    }
                }
            }

            if (toolRar2john == null)
                return null;

            // Check if Python is available
            if (!IsPythonAvailable())
                return null;

            try
            {
                // Use configured Python path if available, otherwise use "python" (from PATH)
                string pythonExe = !string.IsNullOrEmpty(_pythonPath) && File.Exists(_pythonPath)
                    ? _pythonPath
                    : "python";

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = pythonExe,
                    Arguments = $"\"{toolRar2john}\" \"{filePath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null)
                    return null;

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    // Output format: filename:$rar5$... or filename:$RAR3$...
                    // Extract just the hash part
                    int colonIndex = output.IndexOf(':');
                    if (colonIndex >= 0 && (output.Contains("$rar5$") || output.Contains("$RAR3$")))
                    {
                        return output.Substring(colonIndex + 1).Trim();
                    }
                }
            }
            catch
            {
                // Failed to run python
                return null;
            }

            return null;
        }

        /// <summary>
        /// Check if Perl is available on the system
        /// </summary>
        public static bool IsPerlAvailable()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "perl",
                    Arguments = "--version",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null)
                    return false;

                process.WaitForExit(5000);
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if Python is available on the system
        /// </summary>
        public static bool IsPythonAvailable()
        {
            try
            {
                // First try configured Python path
                string pythonExe = !string.IsNullOrEmpty(_pythonPath) && File.Exists(_pythonPath)
                    ? _pythonPath
                    : "python";

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = pythonExe,
                    Arguments = "--version",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null)
                    return false;

                process.WaitForExit(5000);
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// ค้นหา ZIP signature ใน SFX (.exe) file
        /// </summary>
        private static HashInfo ExtractZipFromSFX(BinaryReader br, string filePath)
        {
            // SFX = Self-Extracting Archive (.exe file with ZIP embedded)
            // ค้นหา PK\x03\x04 signature ใน file

            const uint ZIP_SIG = 0x04034b50;
            const int MAX_SEARCH = 10 * 1024 * 1024; // ค้นหา 10MB แรก

            long searchLimit = Math.Min(br.BaseStream.Length, MAX_SEARCH);

            for (long pos = 0; pos < searchLimit - 4; pos++)
            {
                br.BaseStream.Position = pos;
                uint sig = br.ReadUInt32();

                if (sig == ZIP_SIG)
                {
                    // เจอ ZIP signature!
                    br.BaseStream.Position = pos;
                    var result = ExtractZipHash(br, filePath);

                    if (result.IsValid)
                    {
                        // เพิ่มข้อความว่าเป็น SFX
                        result.ErrorMessage = $"ZIP SFX detected at offset 0x{pos:X}";
                        return result;
                    }
                }
            }

            // ไม่เจอ ZIP signature ใน .exe file
            return new HashInfo
            {
                IsValid = false,
                ErrorMessage = "This .exe file does not contain an encrypted ZIP archive (not a ZIP SFX)"
            };
        }

        /// <summary>
        /// รับชื่อ compression type
        /// </summary>
        public static string GetCompressionName(int compression)
        {
            return compression switch
            {
                0 => "Store (Uncompressed)",
                1 => "Shrink",
                2 => "Reduce-1",
                3 => "Reduce-2",
                4 => "Reduce-3",
                5 => "Reduce-4",
                6 => "Implode",
                8 => "Deflate",
                9 => "Deflate64",
                12 => "BZIP2",
                14 => "LZMA",
                95 => "XZ",
                96 => "JPEG",
                97 => "WavPack",
                98 => "PPMd",
                99 => "WinZip AES",
                _ => $"Unknown ({compression})"
            };
        }

        /// <summary>
        /// รับคำอธิบาย Hashcat mode
        /// </summary>
        public static string GetHashcatModeDescription(int mode)
        {
            return mode switch
            {
                17200 => "PKZIP (Deflate)",
                17210 => "PKZIP (Store)",
                17220 => "PKZIP (Deflate64)",
                17225 => "PKZIP (LZMA)",
                17230 => "PKZIP (Reduce)",
                13600 => "WinZip AES",
                12500 => "RAR3 (deprecated)",
                23800 => "RAR3-p (with file check)",
                13000 => "RAR5",
                11600 => "7-Zip",
                _ => $"Unknown mode ({mode})"
            };
        }
    }
}
