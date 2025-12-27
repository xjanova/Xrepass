using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ZipCrackerUI
{
    /// <summary>
    /// ตรวจสอบและจัดการ hash format ของ archive ประเภทต่างๆ
    /// รองรับ: ZIP (PKZIP, ZipCrypto, WinZip AES), RAR3, RAR5
    /// </summary>
    public class HashFormatDetector
    {
        public enum HashType
        {
            Unknown,
            PKZIP_Traditional,  // Mode 17200-17230
            WinZip_AES,         // Mode 13600
            ZIP2_John,          // Mode 13600 (old format)
            RAR3,               // Mode 12500 (old RAR)
            RAR5,               // Mode 13000
            SevenZip            // Mode 11600
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
        /// ตรวจสอบและสร้าง hash ตามประเภทของไฟล์
        /// รองรับ: ZIP (รวม SFX .exe), RAR, 7z
        /// </summary>
        public static HashInfo ExtractHash(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = "File not found"
                };
            }

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

                // อ่าน signature
                var sig = br.ReadUInt32();
                fs.Position = 0;

                // ZIP signature (PK\x03\x04 = 0x04034b50)
                if (sig == 0x04034b50)
                {
                    return ExtractZipHash(br, filePath);
                }

                // RAR signature (Rar!\x1a\x07 = 0x21726152)
                if (sig == 0x21726152)
                {
                    return ExtractRarHash(br, filePath);
                }

                // 7z signature (7z\xbc\xaf\x27\x1c)
                if ((sig & 0xFFFFFF) == 0xAFBC7A37)
                {
                    return Extract7zHash(br, filePath);
                }

                // MZ signature (EXE/DLL = 0x5a4d = "MZ")
                // อาจเป็น ZIP SFX (.exe) - ต้องค้นหา ZIP signature ข้างใน
                if ((sig & 0xFFFF) == 0x5A4D)
                {
                    return ExtractZipFromSFX(br, filePath);
                }

                return new HashInfo
                {
                    IsValid = false,
                    ErrorMessage = $"Unsupported file format (signature: 0x{sig:X8}). Only ZIP, RAR, 7z, and ZIP SFX (.exe) are supported."
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
                    for (int i = 0; i < extraData.Length - 4; i++)
                    {
                        if (extraData[i] == 0x01 && extraData[i + 1] == 0x99)
                        {
                            isWinZipAES = true;
                            // AES strength: 1=128-bit, 2=192-bit, 3=256-bit
                            if (i + 4 < extraData.Length)
                                aesStrength = extraData[i + 4];
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
                        return ExtractWinZipAESHash(br, fileName, compression, aesStrength, dataOffset, (int)compSize);
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
        /// Format: $zip2$*type*mode*magic*salt*verify*compress_length*data*auth_length*auth*$/zip2$
        /// </summary>
        private static HashInfo ExtractWinZipAESHash(BinaryReader br, string fileName, int compression,
            int aesStrength, long dataOffset, int compSize)
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

            // Limit encrypted data for hash (max 32KB to keep hash reasonable)
            int dataToHash = Math.Min(encryptedDataSize, 32768);
            var encData = new byte[dataToHash];
            Array.Copy(allData, saltSize + pvSize, encData, 0, dataToHash);

            // Build hash string in format for Hashcat mode 13600:
            // $zip2$*type*mode*magic*salt*verify*compress_length*data*auth_length*auth*$/zip2$
            // Where:
            // - type = 0 (reserved)
            // - mode = 1/2/3 for AES strength
            // - magic = 0 (reserved)
            // - salt = hex encoded salt
            // - verify = hex encoded password verification
            // - compress_length = length of compressed data in hex
            // - data = hex encoded encrypted data (first portion)
            // - auth_length = length of auth code (always 10)
            // - auth = hex encoded authentication code

            var sb = new StringBuilder();
            sb.Append("$zip2$*");
            sb.Append("0*");                    // type
            sb.Append($"{aesStrength}*");       // mode (1=128, 2=192, 3=256)
            sb.Append("0*");                    // magic

            // Salt (hex)
            foreach (var b in salt)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Password verification (hex)
            foreach (var b in pv)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Compressed data length (hex)
            sb.Append($"{dataToHash:x}*");

            // Encrypted data (hex)
            foreach (var b in encData)
                sb.Append(b.ToString("x2"));
            sb.Append("*");

            // Auth code length
            sb.Append($"{authCodeSize:x}*");

            // Auth code (hex)
            foreach (var b in authCode)
                sb.Append(b.ToString("x2"));

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
            return new HashInfo
            {
                Type = HashType.RAR5,
                HashcatMode = 13000,
                Hash = null,
                FileName = filePath,
                IsValid = false,
                ErrorMessage = "RAR5 detected but could not extract hash. Use rar2john tool to extract hash."
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

            return new HashInfo
            {
                Type = HashType.RAR3,
                HashcatMode = 12500,
                Hash = null,
                FileName = filePath,
                IsValid = false,
                ErrorMessage = "RAR3 detected but could not extract hash. Use rar2john tool to extract hash."
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
        /// Format: $7z$type$numiters$salt$iv$encrypted_data$crc32$datalength
        /// </summary>
        private static HashInfo Extract7zHash(BinaryReader br, string filePath)
        {
            // 7-Zip format is complex - the encryption parameters are in the header
            // For simplicity, we'll try basic extraction or return error

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

                // Read version
                byte majorVer = br.ReadByte();
                byte minorVer = br.ReadByte();

                // Read start header CRC
                uint startHeaderCrc = br.ReadUInt32();

                // Read next header offset and size
                long nextHeaderOffset = br.ReadInt64();
                long nextHeaderSize = br.ReadInt64();
                uint nextHeaderCrc = br.ReadUInt32();

                // For encrypted 7z, we need to parse the headers which is very complex
                // The encryption info is in the encoded header section

                // For now, provide guidance to use 7z2john
                return new HashInfo
                {
                    Type = HashType.SevenZip,
                    HashcatMode = 11600,
                    Hash = null,
                    FileName = filePath,
                    IsValid = false,
                    ErrorMessage = "7-Zip detected. Use 7z2john tool to extract hash for Hashcat mode 11600."
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
                    ErrorMessage = $"7-Zip parsing error: {ex.Message}. Use 7z2john tool."
                };
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
