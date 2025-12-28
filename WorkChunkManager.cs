using System;
using System.Collections.Concurrent;
using System.Numerics;
using System.Threading;

namespace ZipCrackerUI
{
    /// <summary>
    /// จัดการการแบ่งงาน (chunks) ระหว่าง CPU และ GPU
    /// รองรับการหยิบงานแบบ dynamic - ใครเสร็จก่อนหยิบงานใหม่
    /// </summary>
    public class WorkChunkManager
    {
        // Charset definitions
        public const string CHARSET_NUMBERS = "0123456789";
        public const string CHARSET_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        public const string CHARSET_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string CHARSET_SPECIAL = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\";

        // Charset options
        public bool UseNumbers { get; set; } = true;
        public bool UseLowercase { get; set; } = true;
        public bool UseUppercase { get; set; } = false;
        public bool UseSpecial { get; set; } = false;

        // Password length range
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 8;

        // Current active charset (computed from options)
        public string ActiveCharset { get; private set; }

        // Total work calculation
        public BigInteger TotalPasswords { get; private set; }
        public BigInteger RemainingPasswords { get; private set; }

        // Chunk management
        private readonly object _lockObj = new object();
        private BigInteger _nextChunkStart = 0;
        private readonly ConcurrentQueue<WorkChunk> _pendingChunks = new ConcurrentQueue<WorkChunk>();

        // Stats per worker
        public WorkerStats CpuStats { get; } = new WorkerStats("CPU");
        public WorkerStats GpuStats { get; } = new WorkerStats("GPU");

        // Events
        public event Action OnWorkCompleted;
        public event Action<string, int> OnPhaseChanged; // worker name, phase number

        // Password found flag
        private volatile bool _passwordFound = false;
        public bool PasswordFound => _passwordFound;
        public string FoundPassword { get; private set; }
        public string FoundBy { get; private set; }

        public WorkChunkManager()
        {
            UpdateCharset();
        }

        /// <summary>
        /// อัปเดต charset ตาม options ที่เลือก
        /// </summary>
        public void UpdateCharset()
        {
            var charset = "";
            if (UseNumbers) charset += CHARSET_NUMBERS;
            if (UseLowercase) charset += CHARSET_LOWERCASE;
            if (UseUppercase) charset += CHARSET_UPPERCASE;
            if (UseSpecial) charset += CHARSET_SPECIAL;

            if (string.IsNullOrEmpty(charset))
            {
                charset = CHARSET_NUMBERS; // Default to numbers
                UseNumbers = true;
            }

            ActiveCharset = charset;
        }

        /// <summary>
        /// คำนวณจำนวน password ทั้งหมดตาม charset และ length
        /// </summary>
        public BigInteger CalculateTotalPasswords()
        {
            UpdateCharset();

            BigInteger total = 0;
            int charsetSize = ActiveCharset.Length;

            for (int len = MinLength; len <= MaxLength; len++)
            {
                total += BigInteger.Pow(charsetSize, len);
            }

            TotalPasswords = total;
            RemainingPasswords = total;
            return total;
        }

        /// <summary>
        /// รีเซ็ตสถานะเริ่มต้นใหม่
        /// </summary>
        public void Reset()
        {
            lock (_lockObj)
            {
                _nextChunkStart = 0;
                _passwordFound = false;
                FoundPassword = null;
                FoundBy = null;

                while (_pendingChunks.TryDequeue(out _)) { }

                CpuStats.Reset();
                GpuStats.Reset();

                CalculateTotalPasswords();
            }
        }

        /// <summary>
        /// หยิบ chunk งานถัดไปสำหรับ worker
        /// </summary>
        /// <param name="workerName">ชื่อ worker (CPU/GPU)</param>
        /// <param name="preferredSize">ขนาด chunk ที่ต้องการ</param>
        /// <returns>WorkChunk หรือ null ถ้าไม่มีงานเหลือ</returns>
        public WorkChunk GetNextChunk(string workerName, long preferredSize)
        {
            if (_passwordFound) return null;

            lock (_lockObj)
            {
                if (_nextChunkStart >= TotalPasswords)
                    return null;

                BigInteger chunkSize = preferredSize;
                BigInteger remaining = TotalPasswords - _nextChunkStart;

                if (chunkSize > remaining)
                    chunkSize = remaining;

                var chunk = new WorkChunk
                {
                    StartIndex = _nextChunkStart,
                    EndIndex = _nextChunkStart + chunkSize - 1,
                    Size = chunkSize,
                    Charset = ActiveCharset,
                    MinLength = MinLength,
                    MaxLength = MaxLength
                };

                _nextChunkStart += chunkSize;
                RemainingPasswords = TotalPasswords - _nextChunkStart;

                // Update stats
                var stats = workerName == "CPU" ? CpuStats : GpuStats;
                stats.CurrentPhase++;
                stats.CurrentChunkSize = (long)chunkSize;
                stats.CurrentChunkProgress = 0;
                stats.ChunkStartIndex = chunk.StartIndex;
                stats.ChunkEndIndex = chunk.EndIndex;

                OnPhaseChanged?.Invoke(workerName, stats.CurrentPhase);

                return chunk;
            }
        }

        /// <summary>
        /// อัปเดตความคืบหน้าของ worker
        /// </summary>
        public void UpdateProgress(string workerName, long testedInChunk, long totalTestedOverall)
        {
            var stats = workerName == "CPU" ? CpuStats : GpuStats;
            stats.CurrentChunkProgress = testedInChunk;
            stats.TotalTested = totalTestedOverall;
        }

        /// <summary>
        /// แจ้งว่าเจอ password แล้ว
        /// </summary>
        public void ReportPasswordFound(string password, string foundBy)
        {
            lock (_lockObj)
            {
                if (_passwordFound) return; // Already found

                _passwordFound = true;
                FoundPassword = password;
                FoundBy = foundBy;
            }
        }

        /// <summary>
        /// แปลง index เป็น password string
        /// </summary>
        public string IndexToPassword(BigInteger index)
        {
            if (ActiveCharset.Length == 0) return "";

            int charsetLen = ActiveCharset.Length;

            // หา length ของ password จาก index
            BigInteger cumulative = 0;
            int targetLength = MinLength;

            for (int len = MinLength; len <= MaxLength; len++)
            {
                BigInteger countAtLength = BigInteger.Pow(charsetLen, len);
                if (index < cumulative + countAtLength)
                {
                    targetLength = len;
                    index -= cumulative;
                    break;
                }
                cumulative += countAtLength;
                targetLength = len + 1;
            }

            if (targetLength > MaxLength) return null;

            // แปลง index เป็น password
            char[] result = new char[targetLength];
            for (int i = targetLength - 1; i >= 0; i--)
            {
                int charIndex = (int)(index % charsetLen);
                result[i] = ActiveCharset[charIndex];
                index /= charsetLen;
            }

            return new string(result);
        }

        /// <summary>
        /// คำนวณขนาด chunk ที่เหมาะสม
        /// CPU: chunk เล็กกว่า (ช้ากว่า)
        /// GPU: chunk ใหญ่กว่า (เร็วกว่า)
        /// </summary>
        public long GetOptimalChunkSize(string workerName, long estimatedSpeed)
        {
            // Target: แต่ละ chunk ใช้เวลาประมาณ 10 วินาที
            const int TARGET_SECONDS = 10;

            if (estimatedSpeed <= 0)
            {
                // Default speeds if not measured yet
                estimatedSpeed = workerName == "CPU" ? 100_000 : 10_000_000;
            }

            long chunkSize = estimatedSpeed * TARGET_SECONDS;

            // Clamp to reasonable range
            if (workerName == "CPU")
            {
                chunkSize = Math.Max(10_000, Math.Min(chunkSize, 10_000_000));
            }
            else
            {
                chunkSize = Math.Max(1_000_000, Math.Min(chunkSize, 1_000_000_000));
            }

            return chunkSize;
        }

        /// <summary>
        /// ดึงข้อมูลสรุป charset
        /// </summary>
        public string GetCharsetSummary()
        {
            var parts = new System.Collections.Generic.List<string>();
            if (UseNumbers) parts.Add("0-9");
            if (UseLowercase) parts.Add("a-z");
            if (UseUppercase) parts.Add("A-Z");
            if (UseSpecial) parts.Add("!@#...");

            return $"{string.Join(" + ", parts)} ({ActiveCharset.Length} chars)";
        }

        /// <summary>
        /// Format BigInteger เป็น string ที่อ่านง่าย
        /// K = Thousand (พัน)
        /// M = Million (ล้าน)
        /// B = Billion (พันล้าน)
        /// T = Trillion (ล้านล้าน)
        /// Q = Quadrillion (พันล้านล้าน)
        /// Qi = Quintillion
        /// Sx = Sextillion
        /// Sp = Septillion
        /// Oc = Octillion
        /// No = Nonillion
        /// Dc = Decillion
        /// </summary>
        public static string FormatBigNumber(BigInteger number)
        {
            if (number < 1000) return number.ToString();

            // Define thresholds and suffixes
            var units = new (BigInteger threshold, string suffix)[]
            {
                (BigInteger.Parse("1000"), "K"),                          // 10^3
                (BigInteger.Parse("1000000"), "M"),                       // 10^6
                (BigInteger.Parse("1000000000"), "B"),                    // 10^9
                (BigInteger.Parse("1000000000000"), "T"),                 // 10^12
                (BigInteger.Parse("1000000000000000"), "Q"),              // 10^15 Quadrillion
                (BigInteger.Parse("1000000000000000000"), "Qi"),          // 10^18 Quintillion
                (BigInteger.Parse("1000000000000000000000"), "Sx"),       // 10^21 Sextillion
                (BigInteger.Parse("1000000000000000000000000"), "Sp"),    // 10^24 Septillion
                (BigInteger.Parse("1000000000000000000000000000"), "Oc"), // 10^27 Octillion
                (BigInteger.Parse("1000000000000000000000000000000"), "No"), // 10^30 Nonillion
                (BigInteger.Parse("1000000000000000000000000000000000"), "Dc"), // 10^33 Decillion
            };

            // Find appropriate unit
            for (int i = units.Length - 1; i >= 0; i--)
            {
                if (number >= units[i].threshold)
                {
                    double value = (double)number / (double)units[i].threshold;
                    if (value >= 100)
                        return $"{value:F0}{units[i].suffix}";
                    if (value >= 10)
                        return $"{value:F1}{units[i].suffix}";
                    return $"{value:F2}{units[i].suffix}";
                }
            }

            return number.ToString();
        }
    }

    /// <summary>
    /// ข้อมูล chunk งาน
    /// </summary>
    public class WorkChunk
    {
        public BigInteger StartIndex { get; set; }
        public BigInteger EndIndex { get; set; }
        public BigInteger Size { get; set; }
        public string Charset { get; set; }
        public int MinLength { get; set; }
        public int MaxLength { get; set; }

        /// <summary>
        /// คำนวณ progress เป็น % ภายใน chunk นี้
        /// </summary>
        public double GetProgress(BigInteger currentIndex)
        {
            if (Size == 0) return 0;
            BigInteger done = currentIndex - StartIndex;
            return (double)done / (double)Size * 100;
        }
    }

    /// <summary>
    /// สถิติของแต่ละ worker
    /// </summary>
    public class WorkerStats
    {
        public string Name { get; }
        public int CurrentPhase { get; set; } = 0;
        public string CurrentPattern { get; set; } = "Idle"; // Pattern description e.g. "Digits 2-char"
        public long CurrentChunkSize { get; set; } = 0;
        public long CurrentChunkProgress { get; set; } = 0;
        public long TotalTested { get; set; } = 0;
        public BigInteger ChunkStartIndex { get; set; }
        public BigInteger ChunkEndIndex { get; set; }
        public string CurrentPassword { get; set; } = "";
        public string Status { get; set; } = "Idle";
        public long Speed { get; set; } = 0;

        public WorkerStats(string name)
        {
            Name = name;
        }

        public void Reset()
        {
            CurrentPhase = 0;
            CurrentPattern = "Idle";
            CurrentChunkSize = 0;
            CurrentChunkProgress = 0;
            TotalTested = 0;
            ChunkStartIndex = 0;
            ChunkEndIndex = 0;
            CurrentPassword = "";
            Status = "Idle";
            Speed = 0;
        }

        /// <summary>
        /// คำนวณ % ภายใน chunk ปัจจุบัน
        /// </summary>
        public double GetChunkProgressPercent()
        {
            if (CurrentChunkSize <= 0) return 0;
            return (double)CurrentChunkProgress / CurrentChunkSize * 100;
        }
    }
}
