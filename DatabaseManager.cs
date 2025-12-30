using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;

namespace ZipCrackerUI
{
    public class CrackSession
    {
        public int Id { get; set; }
        public string FilePath { get; set; }
        public string FileHash { get; set; }  // MD5 of file for identification
        public string ArchiveType { get; set; }
        public string FoundPassword { get; set; }
        public long TotalAttempts { get; set; }
        public long PasswordsTested { get; set; }
        public double ProgressPercent { get; set; }
        public string LastPasswordTested { get; set; }
        public string AttackMode { get; set; }
        public int MinLength { get; set; }
        public int MaxLength { get; set; }
        public string Pattern { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public bool IsCompleted { get; set; }
        public bool IsCracked { get; set; }
    }

    public class AppSettings
    {
        public string HashcatPath { get; set; }
        public int DefaultThreads { get; set; }
        public bool AutoStartGpu { get; set; }
        public string Theme { get; set; }
    }

    public class DatabaseManager : IDisposable
    {
        private readonly string _dbPath;
        private SqliteConnection _connection;

        public DatabaseManager()
        {
            var appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "X-Repass");
            Directory.CreateDirectory(appDataDir);
            _dbPath = Path.Combine(appDataDir, "xrepass.db");

            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            _connection = new SqliteConnection($"Data Source={_dbPath}");
            _connection.Open();

            // Create tables
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS Settings (
                    Key TEXT PRIMARY KEY,
                    Value TEXT
                );

                CREATE TABLE IF NOT EXISTS CrackSessions (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT NOT NULL,
                    FileHash TEXT,
                    ArchiveType TEXT,
                    FoundPassword TEXT,
                    TotalAttempts INTEGER DEFAULT 0,
                    PasswordsTested INTEGER DEFAULT 0,
                    ProgressPercent REAL DEFAULT 0,
                    LastPasswordTested TEXT,
                    AttackMode TEXT,
                    MinLength INTEGER DEFAULT 1,
                    MaxLength INTEGER DEFAULT 8,
                    Pattern TEXT,
                    CreatedAt TEXT,
                    UpdatedAt TEXT,
                    IsCompleted INTEGER DEFAULT 0,
                    IsCracked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS TestedPasswords (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    SessionId INTEGER,
                    Password TEXT,
                    TestedAt TEXT,
                    FOREIGN KEY (SessionId) REFERENCES CrackSessions(Id)
                );

                CREATE TABLE IF NOT EXISTS PasswordRanges (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    SessionId INTEGER,
                    RangeStart TEXT,
                    RangeEnd TEXT,
                    IsCompleted INTEGER DEFAULT 0,
                    FOREIGN KEY (SessionId) REFERENCES CrackSessions(Id)
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_filepath ON CrackSessions(FilePath);
                CREATE INDEX IF NOT EXISTS idx_sessions_filehash ON CrackSessions(FileHash);
                CREATE INDEX IF NOT EXISTS idx_tested_sessionid ON TestedPasswords(SessionId);
            ";
            cmd.ExecuteNonQuery();
        }

        #region Settings

        public void SaveSetting(string key, string value)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "INSERT OR REPLACE INTO Settings (Key, Value) VALUES (@key, @value)";
            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@value", value);
            cmd.ExecuteNonQuery();
        }

        public string GetSetting(string key, string defaultValue = null)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT Value FROM Settings WHERE Key = @key";
            cmd.Parameters.AddWithValue("@key", key);
            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? defaultValue;
        }

        public AppSettings GetAppSettings()
        {
            return new AppSettings
            {
                HashcatPath = GetSetting("HashcatPath", ""),
                DefaultThreads = int.TryParse(GetSetting("DefaultThreads", "8"), out int t) ? t : 8,
                AutoStartGpu = GetSetting("AutoStartGpu", "false") == "true",
                Theme = GetSetting("Theme", "neon")
            };
        }

        public void SaveAppSettings(AppSettings settings)
        {
            SaveSetting("HashcatPath", settings.HashcatPath);
            SaveSetting("DefaultThreads", settings.DefaultThreads.ToString());
            SaveSetting("AutoStartGpu", settings.AutoStartGpu ? "true" : "false");
            SaveSetting("Theme", settings.Theme);
        }

        #endregion

        #region Crack Sessions

        public int CreateSession(string filePath, string fileHash, string archiveType)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO CrackSessions (FilePath, FileHash, ArchiveType, CreatedAt, UpdatedAt)
                VALUES (@filePath, @fileHash, @archiveType, @now, @now);
                SELECT last_insert_rowid();
            ";
            cmd.Parameters.AddWithValue("@filePath", filePath);
            cmd.Parameters.AddWithValue("@fileHash", fileHash ?? "");
            cmd.Parameters.AddWithValue("@archiveType", archiveType ?? "Unknown");
            cmd.Parameters.AddWithValue("@now", DateTime.Now.ToString("o"));

            return Convert.ToInt32(cmd.ExecuteScalar());
        }

        public CrackSession GetSessionByFileHash(string fileHash)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT * FROM CrackSessions WHERE FileHash = @hash ORDER BY UpdatedAt DESC LIMIT 1";
            cmd.Parameters.AddWithValue("@hash", fileHash);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return ReadSession(reader);
            }
            return null;
        }

        public CrackSession GetSessionByFilePath(string filePath)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT * FROM CrackSessions WHERE FilePath = @path ORDER BY UpdatedAt DESC LIMIT 1";
            cmd.Parameters.AddWithValue("@path", filePath);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return ReadSession(reader);
            }
            return null;
        }

        public void UpdateSessionProgress(int sessionId, long passwordsTested, double progressPercent, string lastPassword)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                UPDATE CrackSessions
                SET PasswordsTested = @tested, ProgressPercent = @progress,
                    LastPasswordTested = @lastPwd, UpdatedAt = @now
                WHERE Id = @id
            ";
            cmd.Parameters.AddWithValue("@id", sessionId);
            cmd.Parameters.AddWithValue("@tested", passwordsTested);
            cmd.Parameters.AddWithValue("@progress", progressPercent);
            cmd.Parameters.AddWithValue("@lastPwd", lastPassword ?? "");
            cmd.Parameters.AddWithValue("@now", DateTime.Now.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        public void MarkSessionCompleted(int sessionId, string foundPassword = null)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                UPDATE CrackSessions
                SET IsCompleted = 1, IsCracked = @cracked, FoundPassword = @pwd, UpdatedAt = @now
                WHERE Id = @id
            ";
            cmd.Parameters.AddWithValue("@id", sessionId);
            cmd.Parameters.AddWithValue("@cracked", foundPassword != null ? 1 : 0);
            cmd.Parameters.AddWithValue("@pwd", foundPassword ?? "");
            cmd.Parameters.AddWithValue("@now", DateTime.Now.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        public void DeleteSession(int sessionId)
        {
            // Delete related tested passwords first
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "DELETE FROM TestedPasswords WHERE SessionId = @id";
            cmd.Parameters.AddWithValue("@id", sessionId);
            cmd.ExecuteNonQuery();

            // Delete password ranges
            cmd = _connection.CreateCommand();
            cmd.CommandText = "DELETE FROM PasswordRanges WHERE SessionId = @id";
            cmd.Parameters.AddWithValue("@id", sessionId);
            cmd.ExecuteNonQuery();

            // Delete the session
            cmd = _connection.CreateCommand();
            cmd.CommandText = "DELETE FROM CrackSessions WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", sessionId);
            cmd.ExecuteNonQuery();
        }

        public List<CrackSession> GetRecentSessions(int limit = 20)
        {
            var sessions = new List<CrackSession>();
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT * FROM CrackSessions ORDER BY UpdatedAt DESC LIMIT @limit";
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                sessions.Add(ReadSession(reader));
            }
            return sessions;
        }

        public List<CrackSession> GetCrackedSessions()
        {
            var sessions = new List<CrackSession>();
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT * FROM CrackSessions WHERE IsCracked = 1 ORDER BY UpdatedAt DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                sessions.Add(ReadSession(reader));
            }
            return sessions;
        }

        private CrackSession ReadSession(SqliteDataReader reader)
        {
            return new CrackSession
            {
                Id = reader.GetInt32(0),
                FilePath = reader.GetString(1),
                FileHash = reader.IsDBNull(2) ? null : reader.GetString(2),
                ArchiveType = reader.IsDBNull(3) ? null : reader.GetString(3),
                FoundPassword = reader.IsDBNull(4) ? null : reader.GetString(4),
                TotalAttempts = reader.IsDBNull(5) ? 0 : reader.GetInt64(5),
                PasswordsTested = reader.IsDBNull(6) ? 0 : reader.GetInt64(6),
                ProgressPercent = reader.IsDBNull(7) ? 0 : reader.GetDouble(7),
                LastPasswordTested = reader.IsDBNull(8) ? null : reader.GetString(8),
                AttackMode = reader.IsDBNull(9) ? null : reader.GetString(9),
                MinLength = reader.IsDBNull(10) ? 1 : reader.GetInt32(10),
                MaxLength = reader.IsDBNull(11) ? 8 : reader.GetInt32(11),
                Pattern = reader.IsDBNull(12) ? null : reader.GetString(12),
                CreatedAt = DateTime.TryParse(reader.IsDBNull(13) ? null : reader.GetString(13), out var c) ? c : DateTime.MinValue,
                UpdatedAt = DateTime.TryParse(reader.IsDBNull(14) ? null : reader.GetString(14), out var u) ? u : DateTime.MinValue,
                IsCompleted = reader.IsDBNull(15) ? false : reader.GetInt32(15) == 1,
                IsCracked = reader.IsDBNull(16) ? false : reader.GetInt32(16) == 1
            };
        }

        #endregion

        #region Tested Passwords

        public void AddTestedPassword(int sessionId, string password)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO TestedPasswords (SessionId, Password, TestedAt)
                VALUES (@sessionId, @pwd, @now)
            ";
            cmd.Parameters.AddWithValue("@sessionId", sessionId);
            cmd.Parameters.AddWithValue("@pwd", password);
            cmd.Parameters.AddWithValue("@now", DateTime.Now.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        public bool IsPasswordTested(int sessionId, string password)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM TestedPasswords WHERE SessionId = @sid AND Password = @pwd";
            cmd.Parameters.AddWithValue("@sid", sessionId);
            cmd.Parameters.AddWithValue("@pwd", password);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        }

        public void AddPasswordRange(int sessionId, string rangeStart, string rangeEnd, bool completed = false)
        {
            var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO PasswordRanges (SessionId, RangeStart, RangeEnd, IsCompleted)
                VALUES (@sid, @start, @end, @completed)
            ";
            cmd.Parameters.AddWithValue("@sid", sessionId);
            cmd.Parameters.AddWithValue("@start", rangeStart);
            cmd.Parameters.AddWithValue("@end", rangeEnd);
            cmd.Parameters.AddWithValue("@completed", completed ? 1 : 0);
            cmd.ExecuteNonQuery();
        }

        #endregion

        #region File Hash

        public static string ComputeFileHash(string filePath)
        {
            try
            {
                using var md5 = System.Security.Cryptography.MD5.Create();
                using var stream = File.OpenRead(filePath);
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        #endregion

        public void Dispose()
        {
            _connection?.Close();
            _connection?.Dispose();
        }
    }
}
