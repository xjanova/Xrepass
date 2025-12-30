using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text.Json;

namespace ZipCrackerUI
{
    /// <summary>
    /// จัดการ Checkpoint - บันทึก/โหลดความคืบหน้าเพื่อป้องกันต้องเริ่มใหม่เมื่อไฟดับหรือค้าง
    /// </summary>
    public class CheckpointManager
    {
        private static readonly string CheckpointDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "X-Repass",
            "Checkpoints");

        /// <summary>
        /// บันทึก checkpoint
        /// </summary>
        public static void SaveCheckpoint(CheckpointData data)
        {
            try
            {
                Directory.CreateDirectory(CheckpointDir);

                // สร้างชื่อไฟล์จาก archive path + timestamp
                string archiveName = Path.GetFileNameWithoutExtension(data.ArchivePath);
                string safeArchiveName = string.Join("_", archiveName.Split(Path.GetInvalidFileNameChars()));
                string checkpointFile = Path.Combine(CheckpointDir, $"{safeArchiveName}_checkpoint.json");

                // Serialize to JSON
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new BigIntegerJsonConverter() }
                };
                string json = JsonSerializer.Serialize(data, options);

                // Save to file
                File.WriteAllText(checkpointFile, json);

                // Also save a backup (in case file gets corrupted during write)
                string backupFile = checkpointFile + ".bak";
                if (File.Exists(checkpointFile))
                    File.Copy(checkpointFile, backupFile, true);
            }
            catch (Exception ex)
            {
                // Silent fail - checkpoint is optional
                System.Diagnostics.Debug.WriteLine($"Checkpoint save failed: {ex.Message}");
            }
        }

        /// <summary>
        /// โหลด checkpoint สำหรับไฟล์นี้
        /// </summary>
        public static CheckpointData LoadCheckpoint(string archivePath)
        {
            try
            {
                if (!Directory.Exists(CheckpointDir))
                    return null;

                string archiveName = Path.GetFileNameWithoutExtension(archivePath);
                string safeArchiveName = string.Join("_", archiveName.Split(Path.GetInvalidFileNameChars()));
                string checkpointFile = Path.Combine(CheckpointDir, $"{safeArchiveName}_checkpoint.json");

                if (!File.Exists(checkpointFile))
                    return null;

                // Read and deserialize
                string json = File.ReadAllText(checkpointFile);
                var options = new JsonSerializerOptions
                {
                    Converters = { new BigIntegerJsonConverter() }
                };
                var data = JsonSerializer.Deserialize<CheckpointData>(json, options);

                // Validate checkpoint is for the same file
                if (data.ArchivePath != archivePath)
                    return null;

                // Check if checkpoint is too old (older than 7 days)
                if ((DateTime.Now - data.LastSaved).TotalDays > 7)
                    return null;

                return data;
            }
            catch (Exception ex)
            {
                // Try backup file
                try
                {
                    string archiveName = Path.GetFileNameWithoutExtension(archivePath);
                    string safeArchiveName = string.Join("_", archiveName.Split(Path.GetInvalidFileNameChars()));
                    string backupFile = Path.Combine(CheckpointDir, $"{safeArchiveName}_checkpoint.json.bak");

                    if (File.Exists(backupFile))
                    {
                        string json = File.ReadAllText(backupFile);
                        var options = new JsonSerializerOptions
                        {
                            Converters = { new BigIntegerJsonConverter() }
                        };
                        return JsonSerializer.Deserialize<CheckpointData>(json, options);
                    }
                }
                catch { }

                System.Diagnostics.Debug.WriteLine($"Checkpoint load failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// ลบ checkpoint สำหรับไฟล์นี้
        /// </summary>
        public static void DeleteCheckpoint(string archivePath)
        {
            try
            {
                if (!Directory.Exists(CheckpointDir))
                    return;

                string archiveName = Path.GetFileNameWithoutExtension(archivePath);
                string safeArchiveName = string.Join("_", archiveName.Split(Path.GetInvalidFileNameChars()));
                string checkpointFile = Path.Combine(CheckpointDir, $"{safeArchiveName}_checkpoint.json");
                string backupFile = checkpointFile + ".bak";

                if (File.Exists(checkpointFile))
                    File.Delete(checkpointFile);
                if (File.Exists(backupFile))
                    File.Delete(backupFile);
            }
            catch { }
        }

        /// <summary>
        /// ดึงรายการ checkpoints ทั้งหมด
        /// </summary>
        public static List<CheckpointInfo> GetAllCheckpoints()
        {
            var result = new List<CheckpointInfo>();

            try
            {
                if (!Directory.Exists(CheckpointDir))
                    return result;

                var files = Directory.GetFiles(CheckpointDir, "*_checkpoint.json");

                foreach (var file in files)
                {
                    try
                    {
                        string json = File.ReadAllText(file);
                        var options = new JsonSerializerOptions
                        {
                            Converters = { new BigIntegerJsonConverter() }
                        };
                        var data = JsonSerializer.Deserialize<CheckpointData>(json, options);

                        if (data != null && File.Exists(data.ArchivePath))
                        {
                            result.Add(new CheckpointInfo
                            {
                                ArchivePath = data.ArchivePath,
                                ArchiveName = Path.GetFileName(data.ArchivePath),
                                LastSaved = data.LastSaved,
                                CpuProgress = CalculateProgressPercent(data.CpuTestedCount, data.TotalPasswords),
                                GpuProgress = data.GpuProgress,
                                AttackMode = data.AttackMode,
                                CpuTestedCount = data.CpuTestedCount,
                                GpuTestedCount = data.GpuTestedCount,
                                ElapsedSeconds = data.ElapsedSeconds,
                                // v1.6: GPU phase info
                                CurrentGpuPhase = data.CurrentGpuPhase,
                                TotalGpuPhases = data.TotalGpuPhases,
                                GpuOverallProgress = data.GpuOverallProgress
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return result.OrderByDescending(x => x.LastSaved).ToList();
        }

        private static double CalculateProgressPercent(long tested, long total)
        {
            if (total <= 0) return 0;
            return Math.Min(100, (double)tested / total * 100);
        }
    }

    /// <summary>
    /// ข้อมูล checkpoint ที่บันทึก
    /// </summary>
    public class CheckpointData
    {
        public string ArchivePath { get; set; }
        public DateTime LastSaved { get; set; }
        public string AttackMode { get; set; }

        // CPU state
        public long CpuTestedCount { get; set; }
        public BigInteger CpuNextChunkStart { get; set; }

        // GPU state
        public long GpuTestedCount { get; set; }
        public int GpuProgress { get; set; }
        public BigInteger GpuNextChunkStart { get; set; }

        // v1.6: GPU phase tracking for multi-phase resume
        public int CurrentGpuPhase { get; set; }
        public int TotalGpuPhases { get; set; }
        public long GpuTotalTestedCount { get; set; }  // Accumulated across all phases
        public double GpuOverallProgress { get; set; } // Overall progress (0-100)

        // Work configuration
        public int MinLength { get; set; }
        public int MaxLength { get; set; }
        public string Charset { get; set; }
        public int ThreadCount { get; set; }

        // Overall stats
        public long TotalPasswords { get; set; }
        public double ElapsedSeconds { get; set; }

        // Custom pattern (if Pattern attack mode)
        public string CustomPattern { get; set; }

        // v1.7: Dictionary resume support
        public long DictionaryLinePosition { get; set; }  // Line number to resume from in dictionary
        public string DictionaryPath { get; set; }        // Path to dictionary file being used

        // v1.5: Dynamic worker switching
        public WorkerConfig WorkerConfiguration { get; set; }
        public WorkerProgress CpuWorkerProgress { get; set; }
        public WorkerProgress GpuWorkerProgress { get; set; }
        public long TotalPasswordSpace { get; set; }
    }

    /// <summary>
    /// Worker configuration - which workers were active
    /// </summary>
    public class WorkerConfig
    {
        public bool UseCpu { get; set; }
        public bool UseGpu { get; set; }
    }

    /// <summary>
    /// Per-worker progress tracking
    /// </summary>
    public class WorkerProgress
    {
        public long StartPosition { get; set; }
        public long CurrentPosition { get; set; }
        public long EndPosition { get; set; }
        public double Speed { get; set; } // passwords/sec
    }

    /// <summary>
    /// ข้อมูลสรุปสำหรับแสดงรายการ checkpoint
    /// </summary>
    public class CheckpointInfo
    {
        public string ArchivePath { get; set; }
        public string ArchiveName { get; set; }
        public DateTime LastSaved { get; set; }
        public double CpuProgress { get; set; }
        public int GpuProgress { get; set; }
        public string AttackMode { get; set; }
        public long CpuTestedCount { get; set; }
        public long GpuTestedCount { get; set; }
        public double ElapsedSeconds { get; set; }

        // v1.6: GPU phase info
        public int CurrentGpuPhase { get; set; }
        public int TotalGpuPhases { get; set; }
        public double GpuOverallProgress { get; set; }

        public string GetDisplayText()
        {
            var elapsed = TimeSpan.FromSeconds(ElapsedSeconds);
            string gpuInfo = TotalGpuPhases > 0
                ? $"GPU: {GpuOverallProgress:F1}% (Phase {CurrentGpuPhase}/{TotalGpuPhases})"
                : $"GPU: {GpuProgress}%";
            return $"{ArchiveName} - {AttackMode} - CPU: {CpuProgress:F1}%, {gpuInfo} - Saved: {LastSaved:yyyy-MM-dd HH:mm:ss} - Elapsed: {elapsed:hh\\:mm\\:ss}";
        }
    }

    /// <summary>
    /// Custom JSON converter for BigInteger
    /// </summary>
    public class BigIntegerJsonConverter : System.Text.Json.Serialization.JsonConverter<BigInteger>
    {
        public override BigInteger Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                string value = reader.GetString();
                return BigInteger.Parse(value);
            }
            else if (reader.TokenType == JsonTokenType.Number)
            {
                return new BigInteger(reader.GetInt64());
            }
            throw new JsonException("Expected string or number for BigInteger");
        }

        public override void Write(Utf8JsonWriter writer, BigInteger value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString());
        }
    }
}
