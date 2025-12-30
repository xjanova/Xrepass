using System;
using System.Reflection;

namespace ZipCrackerUI
{
    /// <summary>
    /// Extensions and helper methods for ZipCrackEngine to enable chunk-based processing.
    /// Provides access to fast password testing without full verification.
    /// </summary>
    public class ZipCrackEngineExtensions
    {
        private readonly ZipCrackEngine _engine;
        private readonly MethodInfo _testPasswordFastMethod;

        // Cached reflection info for encrypted header and validation data
        private readonly FieldInfo _encryptedHeaderField;
        private readonly FieldInfo _expectedCrcHighField;
        private readonly FieldInfo _expectedModTimeField;
        private readonly FieldInfo _isRarArchiveField;

        // CRC32 table for PKZIP decryption
        private static readonly uint[] Crc32Table = GenerateCrc32Table();

        public ZipCrackEngineExtensions(ZipCrackEngine engine)
        {
            _engine = engine ?? throw new ArgumentNullException(nameof(engine));

            // Use reflection to access private method
            var engineType = typeof(ZipCrackEngine);
            _testPasswordFastMethod = engineType.GetMethod("TestPasswordFast",
                BindingFlags.NonPublic | BindingFlags.Instance);

            // Get private fields for direct fast testing
            _encryptedHeaderField = engineType.GetField("_encryptedHeader",
                BindingFlags.NonPublic | BindingFlags.Instance);
            _expectedCrcHighField = engineType.GetField("_expectedCrcHigh",
                BindingFlags.NonPublic | BindingFlags.Instance);
            _expectedModTimeField = engineType.GetField("_expectedModTime",
                BindingFlags.NonPublic | BindingFlags.Instance);
            _isRarArchiveField = engineType.GetField("IsRarArchive",
                BindingFlags.Public | BindingFlags.Instance);
        }

        /// <summary>
        /// Fast password test using the engine's internal method via reflection.
        /// This is faster than VerifyPassword as it only does header check, not full extraction.
        /// </summary>
        public bool TestPasswordFast(string password)
        {
            if (_testPasswordFastMethod != null)
            {
                try
                {
                    return (bool)_testPasswordFastMethod.Invoke(_engine, new object[] { password });
                }
                catch
                {
                    // Fallback to full verification
                    return _engine.VerifyPassword(password);
                }
            }

            // If reflection failed, try direct implementation
            return TestPasswordFastDirect(password);
        }

        /// <summary>
        /// Direct implementation of fast password testing (duplicates engine logic).
        /// This avoids reflection overhead while maintaining fast header-only checks.
        /// </summary>
        public bool TestPasswordFastDirect(string password)
        {
            try
            {
                // Check if already tested
                if (_engine.IsPasswordTestedFunc != null && _engine.IsPasswordTestedFunc(password))
                    return false;

                // For RAR archives, must use full verification
                bool isRar = (bool)(_isRarArchiveField?.GetValue(_engine) ?? false);
                if (isRar)
                    return true; // Will verify with WinRAR

                // Get encrypted header data
                var encryptedHeader = _encryptedHeaderField?.GetValue(_engine) as byte[];
                if (encryptedHeader == null || encryptedHeader.Length < 12)
                    return false;

                var expectedCrcHigh = (uint)(_expectedCrcHighField?.GetValue(_engine) ?? 0);
                var expectedModTime = (ushort)(_expectedModTimeField?.GetValue(_engine) ?? 0);

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
                    lastByte = (byte)(encryptedHeader[i] ^ decByte);

                    key0 = Crc32Table[(key0 ^ lastByte) & 0xFF] ^ (key0 >> 8);
                    key1 = (key1 + (key0 & 0xFF)) * 134775813 + 1;
                    key2 = Crc32Table[(key2 ^ (byte)(key1 >> 24)) & 0xFF] ^ (key2 >> 8);
                }

                return lastByte == expectedCrcHigh || lastByte == (byte)(expectedModTime >> 8);
            }
            catch
            {
                // If anything fails, fall back to full verification
                return _engine.VerifyPassword(password);
            }
        }

        /// <summary>
        /// Full password verification (delegates to engine).
        /// </summary>
        public bool VerifyPassword(string password)
        {
            return _engine.VerifyPassword(password);
        }

        /// <summary>
        /// Generate CRC32 lookup table.
        /// </summary>
        private static uint[] GenerateCrc32Table()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int j = 0; j < 8; j++)
                {
                    if ((c & 1) != 0)
                        c = 0xEDB88320 ^ (c >> 1);
                    else
                        c >>= 1;
                }
                table[i] = c;
            }
            return table;
        }
    }
}
