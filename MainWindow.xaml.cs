using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Controls;
using System.Windows.Shapes;
using System.Windows.Threading;
using Path = System.IO.Path;

namespace ZipCrackerUI
{
    /// <summary>
    /// Attack Strategy Mode - determines the order of password testing
    /// </summary>
    public enum AttackStrategy
    {
        /// <summary>
        /// 🚀 Length-First: Test all patterns for length 1, then 2, then 3...
        /// Best for: Short passwords (most common)
        /// </summary>
        LengthFirst,

        /// <summary>
        /// 🎯 Pattern-First: Test all lengths for pattern 1 (numbers), then pattern 2 (lowercase)...
        /// Best for: When you know the password type
        /// </summary>
        PatternFirst,

        /// <summary>
        /// 🔀 Smart Mix: Interleave lengths and patterns intelligently
        /// Best for: Unknown password characteristics
        /// </summary>
        SmartMix,

        /// <summary>
        /// ⭐ Common-First: Test common passwords first, then PIN codes, then brute force
        /// Best for: Lazy users with common passwords
        /// </summary>
        CommonFirst
    }

    /// <summary>
    /// Strategy item for ComboBox display
    /// </summary>
    public class StrategyItem
    {
        public string Icon { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public AttackStrategy Strategy { get; set; }
    }

    public partial class MainWindow : Window
    {
        private ZipCrackEngine _engine;
        private DispatcherTimer _updateTimer;
        private Stopwatch _stopwatch;
        private Process _hashcatProcess;
        private CancellationTokenSource _gpuCts;
        private CancellationTokenSource _masterCts; // Master cancellation for both CPU and GPU
        private long _gpuSpeed;
        private long _cpuSpeed;
        private double _gpuProgress;  // GPU progress percentage (0-100) for CURRENT phase
        private double _gpuOverallProgress;  // GPU TOTAL progress (0-100) - never decreases until reset
        private long _gpuTestedCount;  // GPU passwords tested in CURRENT phase
        private long _gpuTotalTestedCount;  // GPU passwords tested ACROSS ALL phases (accumulated)
        private long _totalPossiblePasswords;  // Total passwords for entire job (CPU + GPU range)
        private long _gpuTotalKeyspace;  // Total keyspace for all GPU phases combined
        private bool _passwordFound;
        private string _foundPassword;

        // Temperature monitoring
        private int _cpuTemp;
        private int _gpuTemp;

        // Graph data
        private List<double> _cpuTempHistory = new List<double>();
        private List<double> _gpuTempHistory = new List<double>();
        private List<double> _cpuUsageHistory = new List<double>();
        private List<double> _gpuUsageHistory = new List<double>();
        private const int MaxGraphPoints = 60;
        private TemperatureGraphHelper _tempGraphHelper;

        // Database
        private DatabaseManager _db;
        private int _currentSessionId;

        private static readonly string AppDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "X-Repass");
        private static readonly string HashcatDir = Path.Combine(AppDataDir, "hashcat");
        private static readonly string HashcatExe = Path.Combine(HashcatDir, "hashcat.exe");
        private static readonly string ToolsDir = Path.Combine(AppDataDir, "tools");
        private static readonly string PerlDir = Path.Combine(ToolsDir, "perl");
        private static readonly string PerlExe = Path.Combine(PerlDir, "perl", "bin", "perl.exe");
        private static readonly string PythonDir = Path.Combine(ToolsDir, "python");
        private static readonly string PythonExe = Path.Combine(PythonDir, "python.exe");
        private static readonly string JohnDir = Path.Combine(ToolsDir, "john");
        private static readonly string JohnRunDir = Path.Combine(JohnDir, "JtR", "run"); // Actual run folder inside JtR subfolder
        private static readonly string SevenZ2JohnPath = Path.Combine(JohnRunDir, "7z2john.pl"); // Use 7z2john from John package
        private static readonly string Rar2JohnPath = Path.Combine(JohnRunDir, "rar2john.exe");
        private static readonly string JohnExePath = Path.Combine(JohnRunDir, "john.exe"); // John the Ripper executable
        private static readonly string TestedPasswordsFile = Path.Combine(AppDataDir, "tested_passwords.txt");
        private static readonly string SettingsFile = Path.Combine(AppDataDir, "settings.txt");
        private static readonly HttpClient _httpClient = new HttpClient() { Timeout = TimeSpan.FromSeconds(30) }; // 30s timeout for large downloads

        // Tool paths from settings
        private string _7z2johnPath;
        private string _perlPath;
        private string _rar2johnPath;
        private string _pythonPath;
        private string _dictionaryPath;

        // Default dictionary paths
        private static readonly string DefaultDictionaryPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wordlists", "common_passwords.txt");
        private static readonly string WordlistDir = Path.Combine(AppDataDir, "wordlists");
        private static readonly string RockyouPath = Path.Combine(WordlistDir, "rockyou.txt");
        private const string RockyouUrl = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt";

        // Skip already tested passwords
        private ConcurrentDictionary<string, byte> _testedPasswords = new ConcurrentDictionary<string, byte>();

        // Firefly animation
        private List<Firefly> _fireflies = new List<Firefly>();
        private DispatcherTimer _fireflyTimer;
        private Random _fireflyRandom = new Random();

        // Work chunk manager
        private WorkChunkManager _workManager;

        // Speedometer
        private double _maxSpeedReached = 0;
        private double _speedometerMaxScale = 100000; // Dynamic max scale

        // Dynamic worker range tracking
        private long _cpuStartPosition = 0;
        private long _cpuEndPosition = 0;
        private long _cpuCurrentPosition = 0;

        private long _gpuStartPosition = 0;
        private long _gpuEndPosition = 0;
        private long _gpuCurrentPosition = 0;

        private long _totalPasswordSpace = 0;
        private bool _isReconfiguring = false;

        // Checkpoint management
        private DispatcherTimer _checkpointTimer;
        private CheckpointData _loadedCheckpoint;
        private bool _isResuming;
        private int _resumeFromGpuPhase = 0;      // GPU phase to resume from
        private int _resumeTotalGpuPhases = 0;    // Total GPU phases at resume time

        // Hash detection cancellation
        private System.Threading.CancellationTokenSource _hashDetectionCts;

        public MainWindow()
        {
            InitializeComponent();

            // Start watchdog service first
            StartWatchdogService();

            // Kill any hanging hashcat processes from previous session
            KillHangingHashcatProcesses();

            InitializeEngine();
            InitializeTimer();
            InitializeDatabase();
            LoadTestedPasswords();
            LoadSettings();

            // Initialize strategy selector
            InitializeStrategyComboBox();

            // Initialize temperature graph
            _tempGraphHelper = new TemperatureGraphHelper(tempGraphCanvas);

            // Set default thread count
            txtThreads.Text = Environment.ProcessorCount.ToString();

            // Initialize work manager
            _workManager = new WorkChunkManager();
            UpdateCharsetInfo();

            Log("X-Repass initialized");
            Log($"CPU Threads available: {Environment.ProcessorCount}");
            Log("Supports: ZIP, RAR, RAR5, SFX, EXE");
            Log("");

            // Load hardware information
            LoadHardwareInfo();

            // Download all required tools on startup
            _ = DownloadAllToolsOnStartupAsync();

            SystemLog("X-Repass Archive Password Recovery initialized.");
            SystemLog("Select an archive file and click START to begin.");

            Log("CPU: Ready for dictionary attack");

            // Initialize firefly animation
            InitializeFireflies();

            // Initialize speedometer gauge
            InitializeSpeedometer();

            // Check for saved checkpoints
            CheckForCheckpointsOnStartup();

            // Register closing event to cleanup
            this.Closing += MainWindow_Closing;
        }

        /// <summary>
        /// Kill any hanging hashcat processes from previous session to prevent GPU conflicts
        /// </summary>
        private void KillHangingHashcatProcesses()
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("hashcat"))
                {
                    try
                    {
                        proc.Kill();
                        proc.WaitForExit(1000);
                        proc.Dispose();
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Watchdog service and heartbeat timer
        private System.Windows.Threading.DispatcherTimer _heartbeatTimer;

        // Counter for auto-save checkpoint and GPU log clear
        private int _heartbeatCounter = 0;
        private int _gpuLogClearCounter = 0;
        private const int CHECKPOINT_SAVE_INTERVAL = 12; // Save every 60 seconds (12 * 5 seconds)
        private const int GPU_LOG_CLEAR_INTERVAL = 2;    // Clear GPU log every 10 seconds (2 * 5 seconds)
        private const int MAX_GPU_LOG_LINES = 100;       // Max lines before auto-clear

        /// <summary>
        /// Start watchdog service for crash detection and hashcat cleanup
        /// </summary>
        private void StartWatchdogService()
        {
            try
            {
                // Start watchdog (only monitors for hangs and kills orphaned hashcat)
                WatchdogService.Instance.Start();

                // NOTE: Do NOT set checkpoint callbacks to watchdog because it runs in background thread
                // and cannot access UI elements safely. Checkpoint is saved from heartbeat timer instead.

                // Start heartbeat timer (every 5 seconds)
                _heartbeatTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(5)
                };
                _heartbeatTimer.Tick += (s, e) =>
                {
                    // Send heartbeat to watchdog (proves UI thread is responsive)
                    WatchdogService.Instance.Heartbeat();

                    // Auto-save checkpoint periodically (runs in UI thread so safe to access UI elements)
                    _heartbeatCounter++;
                    if (_heartbeatCounter >= CHECKPOINT_SAVE_INTERVAL && (_engine?.IsRunning == true || (_hashcatProcess != null && !_hashcatProcess.HasExited)))
                    {
                        _heartbeatCounter = 0;
                        try
                        {
                            SaveCheckpoint();
                        }
                        catch { }
                    }

                    // Auto-clear GPU log every 10 seconds to prevent UI freeze from too many log lines
                    _gpuLogClearCounter++;
                    if (_gpuLogClearCounter >= GPU_LOG_CLEAR_INTERVAL)
                    {
                        _gpuLogClearCounter = 0;
                        try
                        {
                            // Only clear if log is too long
                            if (txtGpuLog.LineCount > MAX_GPU_LOG_LINES)
                            {
                                // Keep last 20 lines for context
                                var lines = txtGpuLog.Text.Split('\n');
                                if (lines.Length > 20)
                                {
                                    var lastLines = lines.Skip(lines.Length - 20);
                                    txtGpuLog.Text = "[Log cleared - showing last 20 lines]\n" + string.Join("\n", lastLines);
                                    txtGpuLog.ScrollToEnd();
                                }
                            }
                        }
                        catch { }
                    }
                };
                _heartbeatTimer.Start();

                System.Diagnostics.Debug.WriteLine("Watchdog service started");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to start watchdog: {ex.Message}");
            }
        }

        /// <summary>
        /// Create checkpoint data for emergency save
        /// </summary>
        private CheckpointData CreateCheckpointData()
        {
            try
            {
                if (string.IsNullOrEmpty(txtFilePath.Text) || !File.Exists(txtFilePath.Text))
                    return null;

                return new CheckpointData
                {
                    ArchivePath = txtFilePath.Text,
                    LastSaved = DateTime.Now,
                    AttackMode = GetCurrentAttackMode(),
                    CpuTestedCount = _engine?.TotalAttempts ?? 0,
                    GpuTestedCount = _gpuTestedCount,
                    GpuProgress = (int)_gpuProgress,
                    CurrentGpuPhase = _currentGpuPhase,
                    TotalGpuPhases = _totalGpuPhases,
                    GpuTotalTestedCount = _gpuTotalTestedCount,
                    GpuOverallProgress = _gpuOverallProgress,
                    MinLength = _engine?.MinLength ?? _workManager?.MinLength ?? 1,
                    MaxLength = _engine?.MaxLength ?? _workManager?.MaxLength ?? 8,
                    Charset = _workManager?.ActiveCharset ?? "",
                    ThreadCount = _engine?.ThreadCount ?? Environment.ProcessorCount,
                    TotalPasswords = _totalPossiblePasswords,
                    ElapsedSeconds = _stopwatch?.Elapsed.TotalSeconds ?? 0,
                    DictionaryLinePosition = _engine?.DictionaryLinePosition ?? 0,
                    DictionaryPath = _dictionaryPath ?? "",
                    WorkerConfiguration = new WorkerConfig
                    {
                        UseCpu = chkCpu?.IsChecked == true,
                        UseGpu = chkGpu?.IsChecked == true
                    },
                    CpuWorkerProgress = new WorkerProgress
                    {
                        StartPosition = _cpuStartPosition,
                        CurrentPosition = _cpuCurrentPosition,
                        EndPosition = _cpuEndPosition,
                        Speed = _cpuSpeed
                    },
                    GpuWorkerProgress = new WorkerProgress
                    {
                        StartPosition = _gpuStartPosition,
                        CurrentPosition = _gpuCurrentPosition,
                        EndPosition = _gpuEndPosition,
                        Speed = _gpuSpeed
                    },
                    TotalPasswordSpace = _totalPasswordSpace
                };
            }
            catch
            {
                return null;
            }
        }

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Cleanup all running processes and tasks
            try
            {
                // Stop watchdog service
                _heartbeatTimer?.Stop();
                WatchdogService.Instance.Stop();

                // Stop engine
                _engine?.Stop();

                // Cancel all tasks
                _masterCts?.Cancel();
                _gpuCts?.Cancel();

                // Kill hashcat process
                if (_hashcatProcess != null && !_hashcatProcess.HasExited)
                {
                    try { _hashcatProcess.Kill(); } catch { }
                    try { _hashcatProcess.WaitForExit(1000); } catch { }
                    try { _hashcatProcess.Dispose(); } catch { }
                }

                // Stop timers
                _updateTimer?.Stop();
                _fireflyTimer?.Stop();
                _stopwatch?.Stop();

                // Kill any remaining hashcat processes
                try
                {
                    foreach (var proc in Process.GetProcessesByName("hashcat"))
                    {
                        try { proc.Kill(); } catch { }
                    }
                }
                catch { }

                // Save final checkpoint before closing
                SaveCheckpoint();

                // Save settings
                SaveSettings();
            }
            catch { }
        }

        private void InitializeDatabase()
        {
            try
            {
                _db = new DatabaseManager();

                // Load settings from database
                var settings = _db.GetAppSettings();
                if (!string.IsNullOrEmpty(settings.HashcatPath) && File.Exists(settings.HashcatPath))
                {
                    txtHashcatPath.Text = settings.HashcatPath;
                }
                if (settings.DefaultThreads > 0)
                {
                    txtThreads.Text = settings.DefaultThreads.ToString();
                }
            }
            catch (Exception ex)
            {
                Log($"Database init warning: {ex.Message}");
            }
        }

        private void LoadTestedPasswords()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(TestedPasswordsFile));
                if (File.Exists(TestedPasswordsFile))
                {
                    var lines = File.ReadAllLines(TestedPasswordsFile);
                    foreach (var line in lines)
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            _testedPasswords.TryAdd(line.Trim(), 0);
                    }
                    Log($"Loaded {_testedPasswords.Count:N0} previously tested passwords (will be skipped)");
                }
            }
            catch (Exception ex)
            {
                Log($"Warning: Could not load tested passwords: {ex.Message}");
            }
        }

        private void SaveTestedPassword(string password)
        {
            if (_testedPasswords.TryAdd(password, 0))
            {
                try
                {
                    File.AppendAllText(TestedPasswordsFile, password + Environment.NewLine);
                }
                catch { }
            }
        }

        private void LoadSettings()
        {
            try
            {
                Directory.CreateDirectory(AppDataDir);
                Directory.CreateDirectory(ToolsDir);

                if (File.Exists(SettingsFile))
                {
                    var lines = File.ReadAllLines(SettingsFile);
                    foreach (var line in lines)
                    {
                        var parts = line.Split('=', 2);
                        if (parts.Length == 2)
                        {
                            var key = parts[0].Trim();
                            var value = parts[1].Trim();

                            if (key == "HashcatPath" && File.Exists(value))
                            {
                                txtHashcatPath.Text = value;
                                Log($"Loaded saved Hashcat path: {value}");
                            }
                            else if (key == "7z2johnPath" && File.Exists(value))
                            {
                                _7z2johnPath = value;
                            }
                            else if (key == "PerlPath" && File.Exists(value))
                            {
                                _perlPath = value;
                            }
                            else if (key == "Rar2johnPath" && File.Exists(value))
                            {
                                _rar2johnPath = value;
                            }
                            else if (key == "DictionaryPath" && File.Exists(value))
                            {
                                _dictionaryPath = value;
                            }
                        }
                    }
                }

                // Check if rar2john exists
                if (string.IsNullOrEmpty(_rar2johnPath) || !File.Exists(_rar2johnPath))
                {
                    // Check default location
                    if (File.Exists(Rar2JohnPath))
                    {
                        _rar2johnPath = Rar2JohnPath;
                    }
                }

                // Check if dictionary path is set, use default if not
                if (string.IsNullOrEmpty(_dictionaryPath) || !File.Exists(_dictionaryPath))
                {
                    if (File.Exists(DefaultDictionaryPath))
                    {
                        _dictionaryPath = DefaultDictionaryPath;
                        Log($"Using default dictionary: {_dictionaryPath}");
                    }
                }

                // Check if 7z2john exists
                if (string.IsNullOrEmpty(_7z2johnPath) || !File.Exists(_7z2johnPath))
                {
                    // Check default location
                    if (File.Exists(SevenZ2JohnPath))
                    {
                        _7z2johnPath = SevenZ2JohnPath;
                    }
                }

                // Check for system-installed Strawberry Perl first (has all required modules)
                const string systemPerlPath = @"C:\Strawberry\perl\bin\perl.exe";
                if (File.Exists(systemPerlPath))
                {
                    _perlPath = systemPerlPath;
                    Log("Using system Strawberry Perl (full installation)");
                }
                else if (string.IsNullOrEmpty(_perlPath) || !File.Exists(_perlPath))
                {
                    // Fall back to portable Perl if system Perl not found
                    if (File.Exists(PerlExe))
                    {
                        _perlPath = PerlExe;
                    }
                }

                // Update HashFormatDetector with tool paths
                HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                HashFormatDetector.SetPerlPath(_perlPath);
                HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                HashFormatDetector.SetPythonPath(_pythonPath);
            }
            catch (Exception ex)
            {
                Log($"Warning: Could not load settings: {ex.Message}");
            }
        }

        private void SaveSettings()
        {
            try
            {
                // Save to database
                if (_db != null)
                {
                    var settings = new AppSettings
                    {
                        HashcatPath = txtHashcatPath.Text,
                        DefaultThreads = int.TryParse(txtThreads.Text, out int t) ? t : Environment.ProcessorCount,
                        AutoStartGpu = chkGpu.IsChecked == true,
                        Theme = "neon"
                    };
                    _db.SaveAppSettings(settings);
                }

                // Also save to file as backup
                Directory.CreateDirectory(AppDataDir);
                var sb = new StringBuilder();
                sb.AppendLine($"HashcatPath={txtHashcatPath.Text}");
                if (!string.IsNullOrEmpty(_7z2johnPath))
                    sb.AppendLine($"7z2johnPath={_7z2johnPath}");
                if (!string.IsNullOrEmpty(_perlPath))
                    sb.AppendLine($"PerlPath={_perlPath}");
                if (!string.IsNullOrEmpty(_rar2johnPath))
                    sb.AppendLine($"Rar2johnPath={_rar2johnPath}");
                if (!string.IsNullOrEmpty(_dictionaryPath))
                    sb.AppendLine($"DictionaryPath={_dictionaryPath}");
                File.WriteAllText(SettingsFile, sb.ToString());
            }
            catch { }
        }

        public bool IsPasswordTested(string password)
        {
            return _testedPasswords.ContainsKey(password);
        }

        private void InitializeEngine()
        {
            _engine = new ZipCrackEngine();

            _engine.OnLog += (msg) =>
            {
                Dispatcher.BeginInvoke(() =>
                {
                    txtLog.AppendText(msg + Environment.NewLine);
                    txtLog.CaretIndex = txtLog.Text.Length;
                    txtLog.ScrollToEnd();
                });
            };

            _engine.OnPasswordTested += (pwd) =>
            {
                SaveTestedPassword(pwd);
                // Update current password display (every 100 passwords for smooth update)
                if (_engine.TotalAttempts % 100 == 0)
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        lblCpuCurrentPassword.Text = pwd;
                        lblCurrentPwd.Text = pwd; // Also update hidden field for compatibility
                    });
                }
            };

            // Note: Progress is now handled by the timer for more accurate overall tracking
            // The timer uses TotalAttempts / TotalPossiblePasswords for consistent progress display

            _engine.OnPasswordFound += (pwd) =>
            {
                // Password found by CPU - stop everything!
                _passwordFound = true;
                _foundPassword = pwd;

                // Cancel everything
                _masterCts?.Cancel();
                _gpuCts?.Cancel();
                try { _hashcatProcess?.Kill(); } catch { }

                Dispatcher.Invoke(() => HandlePasswordFound(pwd, "CPU"));
            };

            _engine.OnStatusChanged += (status) =>
            {
                Dispatcher.BeginInvoke(() =>
                {
                    lblStatus.Text = status;
                });
            };

            // Handle pattern changes from engine
            _engine.OnPatternChanged += (pattern) =>
            {
                Dispatcher.BeginInvoke(() =>
                {
                    lblCpuPattern.Text = pattern;
                    lblCpuHeaderPattern.Text = pattern.ToUpper();
                    if (_workManager != null)
                    {
                        _workManager.CpuStats.CurrentPattern = pattern;
                    }
                });
            };

            // Set the skip check function
            _engine.IsPasswordTestedFunc = IsPasswordTested;
        }

        private async void UpdateFileInfoDisplay()
        {
            // ยกเลิกการสแกนก่อนหน้า (ถ้ามี)
            _hashDetectionCts?.Cancel();
            _hashDetectionCts?.Dispose();
            _hashDetectionCts = new System.Threading.CancellationTokenSource();

            if (string.IsNullOrEmpty(txtFilePath.Text))
            {
                lblFileNameLarge.Text = "--";
                lblFileSizeLarge.Text = "--";
                lblHashTypeLarge.Text = "--";
                lblHashcatModeLarge.Text = "--";
                return;
            }

            try
            {
                var fi = new FileInfo(txtFilePath.Text);
                lblFileNameLarge.Text = fi.Name;

                // Format file size
                double sizeKB = fi.Length / 1024.0;
                double sizeMB = sizeKB / 1024.0;
                lblFileSizeLarge.Text = sizeMB >= 1 ? $"{sizeMB:F2} MB" : $"{sizeKB:F1} KB";

                // Show "Detecting..." while scanning
                lblHashTypeLarge.Text = "Detecting...";
                lblHashcatModeLarge.Text = "...";

                // Get hash info (async - ไม่บล็อก UI) - พร้อม retry อัตโนมัติ
                Log($"Detecting archive format for: {fi.Name} ({fi.Length} bytes)");
                var hashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                    txtFilePath.Text,
                    maxRetries: 3,
                    timeoutMs: 8000,
                    onRetry: (attempt, max, error) => Log($"Detection retry {attempt}/{max}..."));
                Log($"Detection complete: {(hashInfo.IsValid ? hashInfo.Type.ToString() : "Unknown")}");

                // ตรวจสอบว่า cancelled หรือไม่
                if (_hashDetectionCts.Token.IsCancellationRequested)
                    return;

                if (hashInfo.IsValid)
                {
                    lblHashTypeLarge.Text = hashInfo.Type.ToString().Replace("_", " ");
                    lblHashcatModeLarge.Text = $"#{hashInfo.HashcatMode}";
                }
                else
                {
                    lblHashTypeLarge.Text = "Unknown";
                    lblHashcatModeLarge.Text = "--";

                    // แสดง error ถ้ามี
                    if (!string.IsNullOrEmpty(hashInfo.ErrorMessage))
                    {
                        Log($"Archive detection: {hashInfo.ErrorMessage}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Cancelled - ไม่ต้องทำอะไร
            }
            catch (Exception ex)
            {
                lblFileNameLarge.Text = Path.GetFileName(txtFilePath.Text);
                lblFileSizeLarge.Text = "--";
                lblHashTypeLarge.Text = "Error";
                lblHashcatModeLarge.Text = "--";
                Log($"Error detecting archive: {ex.Message}");
            }
        }

        private void HandlePasswordFound(string password, string foundBy)
        {
            try
            {
                // Ensure we're on UI thread
                if (!Dispatcher.CheckAccess())
                {
                    Dispatcher.Invoke(() => HandlePasswordFound(password, foundBy));
                    return;
                }

                // IMPORTANT: Verify the password actually works before declaring success
                Log($"[VERIFY] Testing password from {foundBy}: {password}");

            bool isValid = false;
            try
            {
                // Use VerifyPassword to actually test the password with 7-Zip or WinRAR
                isValid = _engine.VerifyPassword(password);
            }
            catch (Exception ex)
            {
                Log($"[VERIFY] Error testing password: {ex.Message}");
                isValid = false;
            }

            if (!isValid)
            {
                // Password doesn't work - continue searching!
                Log($"[VERIFY] ❌ Password '{password}' from {foundBy} FAILED verification - continuing search...");
                SystemLog($"⚠️ False positive from {foundBy}: '{password}' - continuing...");

                // Reset the found flag so search continues
                _passwordFound = false;
                _foundPassword = null;

                // Don't stop the search - just return
                return;
            }

            Log($"[VERIFY] ✅ Password '{password}' VERIFIED successfully!");

            // Stop everything - password is confirmed working
            _engine.Stop();
            _gpuCts?.Cancel();
            try { _hashcatProcess?.Kill(); } catch { }

            _stopwatch?.Stop();
            _updateTimer?.Stop();
            _checkpointTimer?.Stop();

            // Delete checkpoint since password was found
            if (!string.IsNullOrEmpty(txtFilePath.Text))
            {
                CheckpointManager.DeleteCheckpoint(txtFilePath.Text);
            }

            // Show overlay on the correct panel based on who found it
            if (foundBy == "CPU")
            {
                borderFoundCpu.Visibility = Visibility.Visible;
                borderFoundGpu.Visibility = Visibility.Collapsed;
                lblFoundPwdCpu.Text = password;
            }
            else
            {
                borderFoundGpu.Visibility = Visibility.Visible;
                borderFoundCpu.Visibility = Visibility.Collapsed;
                lblFoundPwdGpu.Text = password;
            }

            lblStatus.Text = $"PASSWORD FOUND by {foundBy}!";
            lblStatus.Foreground = FindResource("SuccessBrush") as System.Windows.Media.SolidColorBrush;

            // Copy to clipboard
            Clipboard.SetText(password);

            // Save to database
            try
            {
                if (_currentSessionId > 0)
                {
                    _db?.MarkSessionCompleted(_currentSessionId, password);
                    Log($"Password saved to database (Session #{_currentSessionId})");
                }
            }
            catch (Exception ex)
            {
                Log($"Database save error: {ex.Message}");
            }

            // Save to file immediately
            try
            {
                string savePath = Path.Combine(Path.GetDirectoryName(txtFilePath.Text), "FOUND_PASSWORD.txt");
                File.WriteAllText(savePath,
                    $"Password: {password}\n" +
                    $"Found by: {foundBy}\n" +
                    $"Found: {DateTime.Now}\n" +
                    $"File: {txtFilePath.Text}\n" +
                    $"CPU Attempts: {_engine.TotalAttempts:N0}\n" +
                    $"Elapsed: {_stopwatch?.Elapsed}");

                // แสดงข้อความเจอรหัสใน Log ฝั่งที่เจอ
                string successMsg = $"\n{'=',50}\n🎉 PASSWORD FOUND: {password}\n{'=',50}\nFound by: {foundBy}\nElapsed: {_stopwatch?.Elapsed}\nAttempts: {_engine.TotalAttempts:N0}\nSaved to: {savePath}\nCopied to clipboard!\n{'=',50}\n";

                if (foundBy == "CPU")
                {
                    Log(successMsg);
                }
                else
                {
                    GpuLog(successMsg);
                }
            }
            catch (Exception ex)
            {
                Log($"Error saving password: {ex.Message}");
            }

            // ไม่แสดง popup - แสดงใน log แทน
            // MessageBox.Show(...) // ลบออก

            // Reset UI
            btnStart.IsEnabled = true;
            btnStop.IsEnabled = false;
            btnBrowse.IsEnabled = true;
            }
            catch (Exception ex)
            {
                Log($"[ERROR] HandlePasswordFound exception: {ex.Message}");
                SystemLog($"Error handling password: {ex.Message}");
            }
        }

        private void InitializeTimer()
        {
            _stopwatch = new Stopwatch();
            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(200)
            };

            // Checkpoint timer - save every 10 seconds
            _checkpointTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(10)
            };
            _checkpointTimer.Tick += CheckpointTimer_Tick;

            _updateTimer.Tick += (s, e) =>
            {
                // Update elapsed time
                lblTime.Text = _stopwatch.Elapsed.ToString(@"hh\:mm\:ss");

                // Check if either CPU or GPU is running
                bool cpuRunning = _engine.IsRunning;
                bool gpuRunning = _hashcatProcess != null && !_hashcatProcess.HasExited;

                // Get CPU tested count (actually tested, not generated)
                long cpuTestedCount = _engine.TotalAttempts;

                // Update CPU current position
                _cpuCurrentPosition = _cpuStartPosition + cpuTestedCount;

                // Calculate CPU progress based on its assigned work range
                double cpuProgress = 0;
                long cpuTotalPasswords = _engine.TotalPossiblePasswords;
                if (cpuTotalPasswords > 0)
                {
                    cpuProgress = (double)cpuTestedCount / cpuTotalPasswords * 100;
                    cpuProgress = Math.Min(cpuProgress, 100);
                }

                // Update CPU stats display
                if (cpuRunning || cpuTestedCount > 0)
                {
                    lblCpuAttempts.Text = cpuTestedCount.ToString("N0");
                    if (_stopwatch.Elapsed.TotalSeconds > 0)
                    {
                        _cpuSpeed = (long)(cpuTestedCount / _stopwatch.Elapsed.TotalSeconds);
                        lblCpuSpeed.Text = $"{_cpuSpeed:N0} /sec";
                    }

                    // Update CPU progress section
                    string action = cpuRunning ? "Testing passwords..." : "Idle";

                    // คำนวณ ETA
                    long cpuRemaining = cpuTotalPasswords - cpuTestedCount;
                    if (cpuRemaining < 0) cpuRemaining = 0;
                    string cpuEta = CalculateEta(cpuRemaining, _cpuSpeed);

                    // ใช้ cpuProgress ที่คำนวณถูกต้องแล้ว
                    string pattern = _workManager?.CpuStats?.CurrentPattern ?? "Dictionary";
                    UpdateCpuProgress(pattern,
                                    cpuTestedCount, cpuProgress,
                                    cpuTestedCount, cpuTotalPasswords, action, cpuEta);
                }

                // Update CPU progress bars (legacy)
                progressBarCpu.Value = cpuProgress;
                lblProgressCpu.Text = $"{cpuProgress:F0}%";
                progressBarCpuLarge.Value = cpuProgress;
                lblProgressCpuLarge.Text = $"{cpuProgress:F1}%";

                // Update GPU current position based on tested count
                if (_gpuEndPosition > _gpuStartPosition)
                {
                    long gpuRange = _gpuEndPosition - _gpuStartPosition;
                    _gpuCurrentPosition = _gpuStartPosition + (long)(gpuRange * _gpuProgress / 100.0);
                }

                // GPU progress - use _gpuProgress from hashcat parsing (already percentage)
                double gpuProgress = Math.Min(_gpuProgress, 100);
                progressBarGpu.Value = gpuProgress;
                lblProgressGpu.Text = $"{gpuProgress:F0}%";
                progressBarGpuLarge.Value = gpuProgress;
                lblProgressGpuLarge.Text = $"{gpuProgress:F1}%";

                // Update GPU progress section
                if (_workManager != null && (gpuRunning || _totalGpuPhases > 0 || _gpuTestedCount > 0 || _gpuTotalTestedCount > 0))
                {
                    var gpuStats = _workManager.GpuStats;
                    string gpuAction = gpuRunning ? "Running Hashcat..." : (_currentGpuPhase > 0 ? "Switching phase..." : "Idle");

                    // Total tested across all phases = accumulated + current phase
                    long gpuAllTestedCount = _gpuTotalTestedCount + _gpuTestedCount;

                    // คำนวณ ETA สำหรับ GPU - ใช้จำนวนที่ทดสอบทั้งหมด
                    long gpuRemaining = (long)(_workManager.TotalPasswords - gpuAllTestedCount);
                    if (gpuRemaining < 0) gpuRemaining = 0;
                    string gpuEta = CalculateEta(gpuRemaining, _gpuSpeed);

                    // ส่ง _gpuProgress (phase progress 0-100%) ไปให้ UpdateGpuProgress คำนวณ overall
                    // gpuAllTestedCount = จำนวนที่ทดสอบทั้งหมดข้าม phases
                    UpdateGpuProgress(gpuStats.CurrentPattern ?? "Mixed",
                                     gpuAllTestedCount, _gpuProgress,
                                     gpuAllTestedCount, (long)_workManager.TotalPasswords, gpuAction, gpuEta);
                }

                // Calculate OVERALL progress
                // Total tested = CPU tested + GPU tested (including accumulated across phases)
                // Progress = (total tested / total possible) * 100
                long gpuTotalTested = _gpuTotalTestedCount + _gpuTestedCount;
                long totalTestedCount = cpuTestedCount + gpuTotalTested;
                double overallProgress = 0;

                if (_totalPossiblePasswords > 0)
                {
                    overallProgress = (double)totalTestedCount / _totalPossiblePasswords * 100;
                    overallProgress = Math.Min(overallProgress, 100);
                }
                else if (_engine.TotalPossiblePasswords > 0)
                {
                    // Fallback: use engine's total if master total not set
                    overallProgress = (double)totalTestedCount / _engine.TotalPossiblePasswords * 100;
                    overallProgress = Math.Min(overallProgress, 100);
                }

                // Update overall progress bars
                progressBar.Value = overallProgress;
                lblProgress.Text = $"{overallProgress:F2}%";
                progressBarLarge.Value = overallProgress;
                lblProgressLarge.Text = $"{overallProgress:F1}%";

                // Update combined stats (CPU + GPU tested)
                lblAttempts.Text = totalTestedCount.ToString("N0");
                long combinedSpeed = _cpuSpeed + _gpuSpeed;
                lblSpeed.Text = $"{combinedSpeed:N0} /sec";

                // Update temperature display
                UpdateTemperatureDisplay();

                // Update line graph
                UpdateGraph();

                // Update speedometer gauge
                UpdateSpeedometer(combinedSpeed);

                // Update monitoring panel stats
                lblTimePanel.Text = _stopwatch.Elapsed.ToString(@"hh\:mm\:ss");
                lblAttemptsPanel.Text = totalTestedCount.ToString("N0");

                // Update top stats (status bar)
                lblSpeedTop.Text = $"{combinedSpeed:N0}";
                lblAttemptsTop.Text = totalTestedCount.ToString("N0");

                // Update status indicator
                if (_engine.IsRunning || (_hashcatProcess != null && !_hashcatProcess.HasExited))
                {
                    statusIndicator.Fill = new SolidColorBrush(Color.FromRgb(255, 170, 0)); // Orange - Running
                }
                else
                {
                    statusIndicator.Fill = FindResource("SuccessBrush") as SolidColorBrush;
                }

                // Save progress to database every 5 seconds
                if (_currentSessionId > 0 && _stopwatch.Elapsed.TotalSeconds % 5 < 0.3)
                {
                    try
                    {
                        _db?.UpdateSessionProgress(_currentSessionId, totalTestedCount, overallProgress, lblCurrentPwd.Text);
                    }
                    catch { }
                }
            };
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Archive File",
                Filter = "All Archives (*.zip;*.rar;*.7z;*.exe;*.sfx)|*.zip;*.rar;*.7z;*.exe;*.sfx|ZIP files (*.zip)|*.zip|RAR files (*.rar)|*.rar|7-Zip files (*.7z)|*.7z|SFX/EXE files (*.exe;*.sfx)|*.exe;*.sfx|All files (*.*)|*.*",
                InitialDirectory = @"F:\GameHouse 2017"
            };

            if (dialog.ShowDialog() == true)
            {
                txtFilePath.Text = dialog.FileName;
                LoadFile(dialog.FileName);
            }
        }

        private void LoadFile(string path)
        {
            txtLog.Clear();
            txtGpuLog.Clear();
            borderFoundCpu.Visibility = Visibility.Collapsed;
            borderFoundGpu.Visibility = Visibility.Collapsed;

            // Restore GPU logo opacity when loading new file
            imgGpuLogo.Opacity = 0.15;

            // Reset progress bars (ทั้งเล็กและใหญ่)
            progressBar.Value = 0;
            lblProgress.Text = "0%";
            progressBarLarge.Value = 0;
            lblProgressLarge.Text = "0.0%";

            progressBarCpu.Value = 0;
            lblProgressCpu.Text = "0%";
            progressBarCpuLarge.Value = 0;
            lblProgressCpuLarge.Text = "0.0%";

            progressBarGpu.Value = 0;
            lblProgressGpu.Text = "0%";
            progressBarGpuLarge.Value = 0;
            lblProgressGpuLarge.Text = "0.0%";

            _passwordFound = false;
            _foundPassword = null;

            // Clear tested passwords cache - start fresh with new file
            _testedPasswords.Clear();

            // Check if checkpoint exists for this file - ask to resume or start fresh
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                var existingCheckpoint = CheckpointManager.LoadCheckpoint(path);
                if (existingCheckpoint != null && existingCheckpoint.CpuTestedCount > 0)
                {
                    var result = MessageBox.Show(
                        $"พบ checkpoint สำหรับไฟล์นี้:\n" +
                        $"- ทดสอบแล้ว: {existingCheckpoint.CpuTestedCount:N0} รหัส\n" +
                        $"- ตำแหน่ง Dictionary: บรรทัด {existingCheckpoint.DictionaryLinePosition:N0}\n" +
                        $"- GPU Progress: {existingCheckpoint.GpuOverallProgress:F1}%\n\n" +
                        $"ต้องการ Resume จากจุดที่หยุดไว้หรือไม่?",
                        "Resume Checkpoint?",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        // Load checkpoint and prepare for resume
                        _loadedCheckpoint = existingCheckpoint;
                        _isResuming = true;
                        _engine.ResumeFromLine = existingCheckpoint.DictionaryLinePosition;
                        if (!string.IsNullOrEmpty(existingCheckpoint.DictionaryPath))
                        {
                            _dictionaryPath = existingCheckpoint.DictionaryPath;
                        }
                        Log($"Will resume from checkpoint: Line {existingCheckpoint.DictionaryLinePosition:N0}");
                    }
                    else
                    {
                        // Start fresh - delete checkpoint
                        CheckpointManager.DeleteCheckpoint(path);
                        _loadedCheckpoint = null;
                        _isResuming = false;
                        _engine.ResumeFromLine = 0;
                        Log("Starting fresh - checkpoint deleted");
                    }
                }
                else
                {
                    _loadedCheckpoint = null;
                    _isResuming = false;
                }
            }

            Log($"Loading archive: {Path.GetFileName(path)}");
            if (_engine.LoadZipFile(path))
            {
                var fi = new FileInfo(path);
                lblFileInfo.Text = $"{fi.Name} ({fi.Length / 1024.0 / 1024.0:F1} MB)";
                lblStatus.Text = "Ready";
                btnStart.IsEnabled = true;

                // Show archive type badge
                archiveTypeBadge.Visibility = Visibility.Visible;
                lblArchiveType.Text = _engine.ArchiveType;

                // Set icon based on archive type
                if (_engine.IsRarArchive)
                {
                    lblArchiveIcon.Text = "📦";
                    lblArchiveType.Foreground = new SolidColorBrush(Color.FromRgb(255, 107, 53)); // Orange for RAR
                }
                else if (_engine.Is7zArchive)
                {
                    lblArchiveIcon.Text = "🗜️";
                    lblArchiveType.Foreground = new SolidColorBrush(Color.FromRgb(255, 215, 0)); // Gold for 7z
                }
                else
                {
                    lblArchiveIcon.Text = "📁";
                    lblArchiveType.Foreground = new SolidColorBrush(Color.FromRgb(0, 245, 255)); // Cyan for ZIP
                }

                // Auto-configure CPU/GPU based on archive type
                if (_engine.IsRarArchive)
                {
                    // RAR - Check if rar2john.exe available for GPU support (no Python needed - native executable)
                    bool hasRar2John = !string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath);

                    chkCpu.IsEnabled = true;
                    chkCpu.IsChecked = true;  // Enable CPU by default
                    chkGpu.IsEnabled = true;  // Always enable GPU for RAR (will auto-download tools if needed)

                    if (hasRar2John)
                    {
                        // GPU ready - tools already installed
                        chkGpu.IsChecked = true;  // Auto-enable GPU

                        Log($"⚠️ RAR encryption detected");
                        Log($"   CPU mode: ✓ Available (uses WinRAR verification)");
                        Log($"   GPU mode: ✓ Ready (rar2john.exe installed)");
                        Log($"   💡 GPU will extract hash using rar2john, then crack with Hashcat");
                    }
                    else
                    {
                        // Tools not ready yet (should be downloading on startup)
                        Log($"⚠️ RAR encryption detected");
                        Log($"   CPU mode: ✓ Available (uses WinRAR verification)");
                        Log($"   GPU mode: ⏳ Tools downloading... please wait");
                        chkGpu.IsChecked = false;
                    }
                }
                else if (_engine.IsWinZipAES || _engine.Is7zArchive)
                {
                    // WinZip AES and 7z - CPU is slower but still works, GPU recommended
                    chkCpu.IsEnabled = true;
                    chkCpu.IsChecked = true;  // Enable CPU by default
                    chkGpu.IsEnabled = true;
                    chkGpu.IsChecked = true;  // Also enable GPU

                    string archiveType = _engine.Is7zArchive ? "7-Zip" : "WinZip AES";
                    Log($"⚠️ {archiveType} encryption detected");
                    Log($"   CPU mode: ✓ Available (slow - uses 7-Zip verification)");
                    Log($"   GPU mode: ✓ Recommended (much faster with Hashcat)");
                }
                else
                {
                    // PKZIP (ZipCrypto) - CPU can fast-check, enable both options
                    chkCpu.IsEnabled = true;
                    chkCpu.IsChecked = true;
                    chkGpu.IsEnabled = true; // Re-enable GPU (in case it was disabled for RAR)
                    // Keep GPU setting as-is (user preference)

                    Log($"✓ PKZIP (ZipCrypto) - CPU mode available (fast header check)");
                }

                // Create/restore database session
                try
                {
                    string fileHash = DatabaseManager.ComputeFileHash(path);
                    var existingSession = _db?.GetSessionByFileHash(fileHash);

                    if (existingSession != null && !existingSession.IsCompleted)
                    {
                        // พบ session เก่า - ถามผู้ใช้ว่าต้องการ Resume หรือเริ่มใหม่
                        var result = MessageBox.Show(
                            $"Found previous session for this file:\n\n" +
                            $"Progress: {existingSession.ProgressPercent:F1}%\n" +
                            $"Started: {existingSession.CreatedAt:yyyy-MM-dd HH:mm}\n\n" +
                            $"Do you want to resume this session?\n\n" +
                            $"Yes = Resume from {existingSession.ProgressPercent:F1}%\n" +
                            $"No = Start fresh (ignore old progress)",
                            "Resume Previous Session?",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Question);

                        if (result == MessageBoxResult.Yes)
                        {
                            // Resume existing session
                            _currentSessionId = existingSession.Id;
                            progressBar.Value = existingSession.ProgressPercent;
                            lblProgress.Text = $"{existingSession.ProgressPercent:F2}%";
                            Log($"📌 Resuming previous session - {existingSession.ProgressPercent:F1}% completed");

                            if (existingSession.IsCracked && !string.IsNullOrEmpty(existingSession.FoundPassword))
                            {
                                Log($"✅ Password was already found: {existingSession.FoundPassword}");
                            }
                        }
                        else
                        {
                            // เริ่มใหม่ - สร้าง session ใหม่ (เก่าจะยังอยู่ใน database)
                            _currentSessionId = _db?.CreateSession(path, fileHash, _engine.ArchiveType) ?? 0;
                            Log($"📌 Starting fresh - new session created");
                        }
                    }
                    else
                    {
                        // Create new session
                        _currentSessionId = _db?.CreateSession(path, fileHash, _engine.ArchiveType) ?? 0;
                        Log($"📌 New session created");
                    }
                }
                catch { }
            }
            else
            {
                lblFileInfo.Text = "Failed to load file";
                btnStart.IsEnabled = false;
                archiveTypeBadge.Visibility = Visibility.Collapsed;
                Log($"❌ Failed to load file: {path}");
                Log("ℹ️ Supported: ZIP (PKZIP/WinZip AES), RAR3/RAR5, 7-Zip, SFX archives");
                Log("");
                Log("⚠️ Common reasons:");
                Log("   1. File is NOT encrypted (no password protection)");
                Log("   2. File is corrupted or incomplete");
                Log("   3. Archive format not supported");

                // แสดง MessageBox เพื่อให้เห็นชัดเจน
                MessageBox.Show(
                    $"Cannot load archive: {Path.GetFileName(path)}\n\n" +
                    $"Common reasons:\n" +
                    $"• File is NOT encrypted (no password)\n" +
                    $"• File is corrupted\n" +
                    $"• Unsupported format\n\n" +
                    $"This tool only works with PASSWORD-PROTECTED archives.",
                    "Cannot Load Archive",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            // Update file info display
            UpdateFileInfoDisplay();
        }

        private async void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            if (!File.Exists(txtFilePath.Text))
            {
                MessageBox.Show("Please select a valid ZIP file first.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            bool useCpu = chkCpu.IsChecked == true;
            bool useGpu = chkGpu.IsChecked == true;

            if (!useCpu && !useGpu)
            {
                MessageBox.Show("Please select at least CPU or GPU mode.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Reset or Resume state
            if (!_isResuming)
            {
                _passwordFound = false;
                _foundPassword = null;
                _gpuSpeed = 0;
                _cpuSpeed = 0;
                _gpuTestedCount = 0;
                _gpuTotalTestedCount = 0;  // Reset accumulated count
                _gpuProgress = 0;
                _gpuOverallProgress = 0;  // Reset overall progress (only on new job start)
                _totalPossiblePasswords = 0;
                _gpuTotalKeyspace = 0;  // Reset total keyspace
                _resumeFromGpuPhase = 0;  // Clear resume state
                _resumeTotalGpuPhases = 0;

                // Reset all progress displays
                ResetProgressSections();

                // Reset engine state for fresh start (this ensures wordlist reader starts from beginning)
                _engine.Reset();
            }
            _masterCts = new CancellationTokenSource();

            // Always reload file to ensure proper initialization
            // This is necessary because TotalAttempts gets reset but _encryptedHeader might be null
            if (string.IsNullOrEmpty(_engine.ZipFilePath) || _engine.ZipFilePath != txtFilePath.Text)
            {
                LoadFile(txtFilePath.Text);
            }

            // Configure engine
            if (int.TryParse(txtMinLen.Text, out int minLen))
                _engine.MinLength = minLen;
            if (int.TryParse(txtMaxLen.Text, out int maxLen))
                _engine.MaxLength = maxLen;
            if (int.TryParse(txtThreads.Text, out int threads))
                _engine.ThreadCount = threads;

            _engine.CustomPattern = txtPattern.Text;
            _engine.EnableUtf8 = false; // UTF-8 disabled

            // Get attack mode and charset from checkboxes
            AttackMode mode = GetAttackModeFromCheckboxes();
            string charset = GetCharsetFromCheckboxes();
            if (string.IsNullOrEmpty(charset))
            {
                MessageBox.Show("Please select at least one character set.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            _engine.CustomCharset = charset; // Set charset for engine to use
            Log($"Charset: {charset} ({charset.Length} characters)");

            // Update UI
            btnStart.IsEnabled = false;
            btnPause.IsEnabled = true;
            btnStop.IsEnabled = true;
            btnBrowse.IsEnabled = false;
            borderFoundCpu.Visibility = Visibility.Collapsed;
            borderFoundGpu.Visibility = Visibility.Collapsed;
            _isPaused = false;
            txtPauseIcon.Text = "⏸";
            txtPauseText.Text = "PAUSE";

            // Reset all progress bars
            progressBar.Value = 0;
            progressBarLarge.Value = 0;
            progressBarCpu.Value = 0;
            progressBarCpuLarge.Value = 0;
            progressBarGpu.Value = 0;
            progressBarGpuLarge.Value = 0;

            txtLog.Clear();
            txtGpuLog.Clear();

            // Restore GPU logo opacity when starting fresh
            imgGpuLogo.Opacity = 0.15;

            // Start timers
            if (_isResuming && _loadedCheckpoint != null)
            {
                // Resume from checkpoint elapsed time
                _stopwatch.Start();
                var elapsed = TimeSpan.FromSeconds(_loadedCheckpoint.ElapsedSeconds);
                _stopwatch = Stopwatch.StartNew();
                // Adjust for resumed time (approximation)
                System.Reflection.FieldInfo elapsedField = typeof(Stopwatch).GetField("_elapsed",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (elapsedField != null)
                    elapsedField.SetValue(_stopwatch, elapsed.Ticks);
                Log($"Resuming from checkpoint (Previous elapsed: {elapsed:hh\\:mm\\:ss})");
                // NOTE: Don't clear _isResuming here - it's needed later for worker position restore
            }
            else
            {
                _stopwatch.Restart();
            }
            _updateTimer.Start();
            _checkpointTimer.Start(); // Start auto-save checkpoint

            Log("");
            SystemLog("");
            if (useCpu && useGpu)
            {
                SystemLog("=== HYBRID ATTACK (CPU + GPU) ===");
                Log("=== CPU: DICTIONARY ATTACK ===");
                GpuLog("=== GPU: BRUTE FORCE ===");
                _engine.IsHybridMode = true;
            }
            else if (useGpu)
            {
                SystemLog("=== GPU ONLY: BRUTE FORCE ===");
                GpuLog("=== GPU: BRUTE FORCE ===");
                _engine.IsHybridMode = false;
            }
            else
            {
                SystemLog("=== CPU ONLY: DICTIONARY ATTACK ===");
                Log("=== CPU: DICTIONARY ATTACK ===");
                _engine.IsHybridMode = false;
            }
            Log("");

            // Detect reconfiguration (worker change during resume)
            if (_isResuming && _loadedCheckpoint != null)
            {
                bool oldUseCpu = _loadedCheckpoint.WorkerConfiguration?.UseCpu ?? true;
                bool oldUseGpu = _loadedCheckpoint.WorkerConfiguration?.UseGpu ?? false;

                if (oldUseCpu != useCpu || oldUseGpu != useGpu)
                {
                    _isReconfiguring = true;
                }

                // Restore ranges from checkpoint
                if (_loadedCheckpoint.CpuWorkerProgress != null)
                {
                    _cpuCurrentPosition = _loadedCheckpoint.CpuWorkerProgress.CurrentPosition;
                    _cpuSpeed = (long)_loadedCheckpoint.CpuWorkerProgress.Speed;
                }
                if (_loadedCheckpoint.GpuWorkerProgress != null)
                {
                    _gpuCurrentPosition = _loadedCheckpoint.GpuWorkerProgress.CurrentPosition;
                    _gpuSpeed = (long)_loadedCheckpoint.GpuWorkerProgress.Speed;
                }
                if (_loadedCheckpoint.TotalPasswordSpace > 0)
                {
                    _totalPasswordSpace = _loadedCheckpoint.TotalPasswordSpace;
                }

                // Restore GPU progress counters
                _gpuTotalTestedCount = _loadedCheckpoint.GpuTotalTestedCount;
                _gpuTestedCount = 0; // Will accumulate in current phase
                _gpuOverallProgress = _loadedCheckpoint.GpuOverallProgress;

                // Store phase info for GPU attack to skip completed phases
                _resumeFromGpuPhase = _loadedCheckpoint.CurrentGpuPhase;
                _resumeTotalGpuPhases = _loadedCheckpoint.TotalGpuPhases;

                Log($"Restoring GPU state: Phase {_resumeFromGpuPhase}/{_resumeTotalGpuPhases}, Tested: {_gpuTotalTestedCount:N0}");

                // Now clear the resume flag after all restore operations are done
                _isResuming = false;
                _loadedCheckpoint = null;
            }

            // Update file info display
            UpdateFileInfoDisplay();

            // Calculate total password space (first time only)
            if (_totalPasswordSpace == 0)
            {
                _totalPasswordSpace = CalculateTotalPossiblePasswords(mode, minLen, maxLen);
            }
            _totalPossiblePasswords = _totalPasswordSpace; // For compatibility
            Log($"Total password space: {_totalPasswordSpace:N0}");

            // Allocate work ranges
            AllocateWorkRanges(useCpu, useGpu);

            // Start attacks in parallel
            var tasks = new System.Collections.Generic.List<Task>();

            // CPU attack mode
            if (useCpu)
            {
                // Find best available dictionary
                string dictPath = null;

                // Priority: 1) rockyou.txt  2) user-specified  3) default
                if (File.Exists(RockyouPath))
                    dictPath = RockyouPath;
                else if (!string.IsNullOrEmpty(_dictionaryPath) && File.Exists(_dictionaryPath))
                    dictPath = _dictionaryPath;
                else if (File.Exists(DefaultDictionaryPath))
                    dictPath = DefaultDictionaryPath;

                if (useGpu)
                {
                    // CPU + GPU hybrid mode: CPU does dictionary only (GPU handles brute force)
                    if (!string.IsNullOrEmpty(dictPath) && File.Exists(dictPath))
                    {
                        var fileInfo = new FileInfo(dictPath);
                        Log($"CPU: Dictionary attack (GPU handles brute force)");
                        Log($"Wordlist: {Path.GetFileName(dictPath)} ({fileInfo.Length / 1024:N0} KB)");
                        SystemLog($"CPU: Dictionary | GPU: Brute force");
                        tasks.Add(_engine.DictionaryFileAttackAsync(dictPath));
                    }
                    else
                    {
                        Log("WARNING: No dictionary file found - CPU skipped");
                        SystemLog("No wordlist found - GPU will handle all work");
                    }
                }
                else
                {
                    // CPU-only mode: Quick brute force 1-3 chars (using selected charset) → then dictionary
                    Log($"CPU-only mode: Brute force 1-3 chars → Dictionary");
                    Log($"Charset: {charset} ({charset.Length} chars)");
                    SystemLog($"CPU-only: Phase 1=Brute force (1-3 chars), Phase 2=Dictionary");

                    if (!string.IsNullOrEmpty(dictPath) && File.Exists(dictPath))
                    {
                        var fileInfo = new FileInfo(dictPath);
                        Log($"Wordlist: {Path.GetFileName(dictPath)} ({fileInfo.Length / 1024:N0} KB)");
                    }

                    tasks.Add(_engine.ShortBruteForceBeforeDictionaryAsync(dictPath, charset, 3));
                }
            }

            // GPU does brute force (all patterns)
            if (useGpu)
            {
                GpuLog("GPU: Brute force attack (all patterns)");
                SystemLog("GPU starting brute force attack");
                tasks.Add(StartGpuAttackAsync());
            }

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                // Expected when password is found
            }

            // Stop timer
            _stopwatch.Stop();
            _updateTimer.Stop();

            // Update UI if not already done by password found
            if (!_passwordFound)
            {
                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;
                btnBrowse.IsEnabled = true;
                lblStatus.Text = "Completed";
            }
        }

        private bool _isPaused = false;

        private void BtnPause_Click(object sender, RoutedEventArgs e)
        {
            _isPaused = !_isPaused;

            if (_isPaused)
            {
                // Pause CPU engine
                _engine.Pause();
                _stopwatch.Stop();
                _updateTimer.Stop();

                // Pause GPU (hashcat) - send 'p' key to pause
                if (_hashcatProcess != null && !_hashcatProcess.HasExited)
                {
                    try
                    {
                        _hashcatProcess.StandardInput.WriteLine("p");
                        _hashcatProcess.StandardInput.Flush();
                        GpuLog("[GPU] Pause signal sent to hashcat");
                    }
                    catch (Exception ex)
                    {
                        GpuLog($"[GPU] Failed to pause: {ex.Message}");
                    }
                }

                txtPauseIcon.Text = "▶";
                txtPauseText.Text = "RESUME";
                lblStatus.Text = "Paused";
                lblGpuStatus.Text = "Paused";

                Log("=== PAUSED ===");
                GpuLog("=== PAUSED ===");
            }
            else
            {
                // Resume CPU engine
                _engine.Resume();
                _stopwatch.Start();
                _updateTimer.Start();

                // Resume GPU (hashcat) - send 'r' key to resume
                if (_hashcatProcess != null && !_hashcatProcess.HasExited)
                {
                    try
                    {
                        _hashcatProcess.StandardInput.WriteLine("r");
                        _hashcatProcess.StandardInput.Flush();
                        GpuLog("[GPU] Resume signal sent to hashcat");
                    }
                    catch (Exception ex)
                    {
                        GpuLog($"[GPU] Failed to resume: {ex.Message}");
                    }
                }

                txtPauseIcon.Text = "⏸";
                txtPauseText.Text = "PAUSE";
                lblStatus.Text = "Running";
                lblGpuStatus.Text = "Running";

                Log("=== RESUMED ===");
                GpuLog("=== RESUMED ===");
            }
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _engine.Stop();

            // Stop GPU
            _masterCts?.Cancel();
            _gpuCts?.Cancel();
            try { _hashcatProcess?.Kill(); } catch { }

            // Stop checkpoint timer
            _checkpointTimer?.Stop();

            // Delete checkpoint - user intentionally cancelled the job
            if (!string.IsNullOrEmpty(txtFilePath.Text))
            {
                CheckpointManager.DeleteCheckpoint(txtFilePath.Text);
            }
            _loadedCheckpoint = null;
            _isResuming = false;

            // Delete session from database - user cancelled so no need to track
            if (_currentSessionId > 0 && _db != null)
            {
                try
                {
                    _db.DeleteSession(_currentSessionId);
                }
                catch { }
                _currentSessionId = 0;
            }

            // Clear tested passwords cache - start fresh next time
            _testedPasswords.Clear();

            // ไม่ปิดการใช้งานปุ่ม STOP - ให้กดได้เสมอ
            btnPause.IsEnabled = false;
            _isPaused = false;
            txtPauseIcon.Text = "⏸";
            txtPauseText.Text = "PAUSE";

            lblStatus.Text = "Stopped";
            lblGpuStatus.Text = "Stopped";

            Log("Job cancelled.");
        }

        private void BtnTest_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new TestPasswordDialog(_engine, txtFilePath.Text);
            dialog.Owner = this;
            dialog.ShowDialog();
        }

        private void BtnCopyCpu_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(lblFoundPwdCpu.Text))
            {
                Clipboard.SetText(lblFoundPwdCpu.Text);
                MessageBox.Show("Password copied to clipboard!", "Copied",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnCopyGpu_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(lblFoundPwdGpu.Text))
            {
                Clipboard.SetText(lblFoundPwdGpu.Text);
                MessageBox.Show("Password copied to clipboard!", "Copied",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnStopFromFound_Click(object sender, RoutedEventArgs e)
        {
            // Stop and cleanup - same as BtnStop_Click but also hide overlays
            BtnStop_Click(sender, e);
            borderFoundCpu.Visibility = Visibility.Collapsed;
            borderFoundGpu.Visibility = Visibility.Collapsed;
        }

        private async void BtnContinue_Click(object sender, RoutedEventArgs e)
        {
            // User says the found password was a false positive - continue searching
            string falsePositive = lblFoundPwdCpu.Text ?? lblFoundPwdGpu.Text;
            Log($"False positive: {falsePositive} - Continuing search...");
            GpuLog($"False positive: {falsePositive} - Continuing search...");

            // Add to tested passwords so it won't be reported again
            SaveTestedPassword(falsePositive);

            // Reset state
            _passwordFound = false;
            _foundPassword = null;
            borderFoundCpu.Visibility = Visibility.Collapsed;
            borderFoundGpu.Visibility = Visibility.Collapsed;

            // Get attack mode from checkboxes
            AttackMode mode = GetAttackModeFromCheckboxes();

            // Restart the attack
            bool useCpu = chkCpu.IsChecked == true;
            bool useGpu = chkGpu.IsChecked == true;

            _masterCts = new CancellationTokenSource();

            // Update UI
            btnStart.IsEnabled = false;
            btnStop.IsEnabled = true;
            btnBrowse.IsEnabled = false;
            lblStatus.Text = "Running";

            // Restart timer if stopped
            if (!_stopwatch.IsRunning)
                _stopwatch.Start();
            if (!_updateTimer.IsEnabled)
                _updateTimer.Start();

            // Start attacks in parallel
            var tasks = new System.Collections.Generic.List<Task>();

            if (useCpu)
            {
                tasks.Add(_engine.StartAttackAsync(mode));
            }

            if (useGpu)
            {
                tasks.Add(StartGpuAttackAsync());
            }

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                // Expected when password is found
            }

            // Stop timer if not found
            if (!_passwordFound)
            {
                _stopwatch.Stop();
                _updateTimer.Stop();
                btnStart.IsEnabled = true;
                btnStop.IsEnabled = false;
                btnBrowse.IsEnabled = true;
                lblStatus.Text = "Completed";
            }
        }

        private void ChkGpu_Checked(object sender, RoutedEventArgs e)
        {
            txtHashcatPath.Visibility = Visibility.Visible;
            txtHashcatPath.IsEnabled = true;
            btnBrowseHashcat.Visibility = Visibility.Visible;
            btnBrowseHashcat.IsEnabled = true;

            // ถ้ามี path ที่ save ไว้แล้วและไฟล์ยังอยู่ → ใช้เลย ไม่ต้องหาใหม่
            if (!string.IsNullOrEmpty(txtHashcatPath.Text) && File.Exists(txtHashcatPath.Text))
            {
                Log($"Using saved Hashcat path: {txtHashcatPath.Text}");
                return;
            }

            // ถ้าไม่มี หรือไฟล์หาย → ค้นหาใหม่
            string[] possiblePaths = {
                HashcatExe,
                @"C:\hashcat\hashcat.exe",
                @"C:\Program Files\hashcat\hashcat.exe",
                @"D:\hashcat\hashcat.exe",
                Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\Downloads\hashcat-6.2.6\hashcat.exe")
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    txtHashcatPath.Text = path;
                    Log($"Found Hashcat: {path}");
                    return;
                }
            }

            Log("Hashcat not found. Please browse to hashcat.exe or download from https://hashcat.net/hashcat/");
        }

        private void ChkGpu_Unchecked(object sender, RoutedEventArgs e)
        {
            txtHashcatPath.Visibility = Visibility.Collapsed;
            txtHashcatPath.IsEnabled = false;
            btnBrowseHashcat.Visibility = Visibility.Collapsed;
            btnBrowseHashcat.IsEnabled = false;
        }

        private void BtnBrowseHashcat_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select hashcat.exe",
                Filter = "Hashcat (hashcat.exe)|hashcat.exe|All executables (*.exe)|*.exe",
                FileName = "hashcat.exe"
            };

            if (dialog.ShowDialog() == true)
            {
                txtHashcatPath.Text = dialog.FileName;
                Log($"Hashcat path set: {dialog.FileName}");
                SaveSettings();
            }
        }

        private async void BtnExtractHash_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtFilePath.Text) || !File.Exists(txtFilePath.Text))
            {
                MessageBox.Show("Please select a ZIP file first.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Show "Extracting..." message
            Log("Extracting hash from archive...");

            // Extract hash using HashFormatDetector พร้อม retry
            var hashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                txtFilePath.Text,
                maxRetries: 3,
                onRetry: (attempt, max, error) => Log($"Retry {attempt}/{max}..."));

            if (!hashInfo.IsValid)
            {
                MessageBox.Show($"Failed to extract hash: {hashInfo.ErrorMessage}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string hash = hashInfo.Hash;
            string hashcatMode = hashInfo.HashcatMode.ToString();

            Clipboard.SetText(hash);
            Log($"Hash extracted and copied to clipboard:");
            Log(hash);
            Log("");
            Log($"Hash Type: {hashInfo.Type}");
            Log($"Hashcat Mode: {hashcatMode} ({HashFormatDetector.GetHashcatModeDescription(hashInfo.HashcatMode)})");
            Log($"Use with Hashcat: hashcat -m {hashcatMode} -a 3 hash.txt ?a?a?a?a?a?a?a?a");

            // Save to file
            string hashFile = Path.Combine(Path.GetDirectoryName(txtFilePath.Text), "archive_hash.txt");
            File.WriteAllText(hashFile, hash);
            Log($"Hash saved to: {hashFile}");

            string hashDesc = HashFormatDetector.GetHashcatModeDescription(hashInfo.HashcatMode);
            MessageBox.Show($"Hash extracted and copied to clipboard!\n\nSaved to: {hashFile}\n\nHashcat mode: {hashcatMode} ({hashDesc})",
                "Hash Extracted", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async Task StartGpuAttackAsync()
        {
            if (string.IsNullOrEmpty(txtHashcatPath.Text) || !File.Exists(txtHashcatPath.Text))
            {
                GpuLog("╔══════════════════════════════════════════════════╗");
                GpuLog("║  ERROR: HASHCAT NOT FOUND!                       ║");
                GpuLog("╚══════════════════════════════════════════════════╝");
                GpuLog("");
                GpuLog("GPU mode requires Hashcat to crack passwords.");
                GpuLog("Without Hashcat, this panel only extracts the hash.");
                GpuLog("");
                GpuLog("To enable GPU cracking:");
                GpuLog("1. Download Hashcat: https://hashcat.net/hashcat/");
                GpuLog("2. Extract to a folder (e.g., C:\\hashcat)");
                GpuLog("3. Go to Settings (gear icon) and set Hashcat path");
                GpuLog("");
                if (!string.IsNullOrEmpty(txtHashcatPath.Text))
                    GpuLog($"Current path (not found): {txtHashcatPath.Text}");

                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Hashcat Not Found");

                // Still extract and show hash for manual use
                GpuLog("");
                GpuLog("=== EXTRACTING HASH FOR MANUAL USE ===");
                var manualHashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                    txtFilePath.Text,
                    maxRetries: 2,
                    onRetry: (attempt, max, error) => GpuLog($"Retry {attempt}/{max}..."));
                if (manualHashInfo.IsValid)
                {
                    GpuLog($"Type: {manualHashInfo.Type}");
                    GpuLog($"Hashcat Mode: {manualHashInfo.HashcatMode}");
                    GpuLog($"Hash: {manualHashInfo.Hash}");
                    GpuLog("");
                    GpuLog("You can copy this hash and crack it manually with:");
                    GpuLog($"  hashcat -m {manualHashInfo.HashcatMode} -a 3 hash.txt ?a?a?a?a");
                }
                return;
            }

            // Extract hash using HashFormatDetector (auto-detects format and mode)
            // ใช้ retry mechanism เพื่อให้มั่นใจว่าจะ extract ได้
            GpuLog("Extracting hash from archive...");
            var hashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                txtFilePath.Text,
                maxRetries: 3,
                onRetry: (attempt, max, error) =>
                {
                    GpuLog($"⚠️ Attempt {attempt}/{max} failed: {error}");
                    GpuLog($"   Retrying with longer timeout...");
                });

            // If 7z and hash extraction failed, try to get 7z2john
            if (!hashInfo.IsValid && hashInfo.Type == HashFormatDetector.HashType.SevenZip)
            {
                GpuLog("7-Zip archive detected - checking for 7z2john tool...");

                // Check if 7z2john exists
                bool has7z2john = false;

                if (!string.IsNullOrEmpty(_7z2johnPath) && File.Exists(_7z2johnPath))
                {
                    has7z2john = true;
                    GpuLog($"Using 7z2john from: {_7z2johnPath}");
                }
                else if (File.Exists(SevenZ2JohnPath))
                {
                    _7z2johnPath = SevenZ2JohnPath;
                    HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                    has7z2john = true;
                    GpuLog($"Using 7z2john from: {SevenZ2JohnPath}");
                }
                else
                {
                    // Not found - download automatically
                    GpuLog("7z2john.pl not found - downloading...");
                    await Download7z2JohnAsync();

                    // Check if download succeeded
                    if (File.Exists(SevenZ2JohnPath))
                    {
                        _7z2johnPath = SevenZ2JohnPath;
                        HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                        has7z2john = true;
                    }
                }

                if (has7z2john)
                {
                    // Always ensure Perl path is set before retrying
                    bool hasPerl = false;
                    if (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath))
                    {
                        HashFormatDetector.SetPerlPath(_perlPath);
                        hasPerl = true;
                        GpuLog($"Using Perl from: {_perlPath}");
                    }
                    else if (File.Exists(PerlExe))
                    {
                        _perlPath = PerlExe;
                        HashFormatDetector.SetPerlPath(_perlPath);
                        hasPerl = true;
                        GpuLog($"Using Perl from: {PerlExe}");
                    }
                    else
                    {
                        // Download Strawberry Perl
                        GpuLog("Perl not found - downloading...");
                        await DownloadStrawberryPerlAsync();

                        // Check if download succeeded
                        if (File.Exists(PerlExe))
                        {
                            _perlPath = PerlExe;
                            HashFormatDetector.SetPerlPath(_perlPath);
                            hasPerl = true;
                            GpuLog($"Using Perl from: {PerlExe}");
                        }
                    }

                    if (!hasPerl)
                    {
                        GpuLog("⚠️ Failed to get Perl - cannot extract hash from 7-Zip");
                        GpuLog("Please install Strawberry Perl manually from: https://strawberryperl.com/");
                        hashInfo = new HashFormatDetector.HashInfo
                        {
                            IsValid = false,
                            ErrorMessage = "Perl installation required but auto-download failed"
                        };
                    }
                    else
                    {
                        // Retry extraction with Perl path set (with retry mechanism)
                        GpuLog("Retrying hash extraction with 7z2john...");
                        hashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                            txtFilePath.Text,
                            maxRetries: 2,
                            onRetry: (attempt, max, error) => GpuLog($"   Retry {attempt}/{max}..."));
                    }
                }
                else
                {
                    GpuLog("⚠️ Failed to get 7z2john.pl - cannot extract hash from 7-Zip");
                }
            }

            // If RAR and hash extraction failed, try to get rar2john
            if (!hashInfo.IsValid && (hashInfo.Type == HashFormatDetector.HashType.RAR3 || hashInfo.Type == HashFormatDetector.HashType.RAR5))
            {
                GpuLog("RAR archive detected - checking for rar2john tool...");

                // Check if rar2john exists
                bool hasRar2john = false;

                if (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath))
                {
                    hasRar2john = true;
                    GpuLog($"Using rar2john from: {_rar2johnPath}");
                }
                else if (File.Exists(Rar2JohnPath))
                {
                    _rar2johnPath = Rar2JohnPath;
                    HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                    hasRar2john = true;
                    GpuLog($"Using rar2john from: {Rar2JohnPath}");
                }
                else
                {
                    // Not found - download automatically
                    GpuLog("rar2john.exe not found - downloading John the Ripper...");
                    await DownloadRar2JohnAsync();

                    // Check if download succeeded
                    if (File.Exists(Rar2JohnPath))
                    {
                        _rar2johnPath = Rar2JohnPath;
                        HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                        hasRar2john = true;
                    }
                }

                if (hasRar2john)
                {
                    // rar2john.exe is now a native executable (no Python required)
                    GpuLog("Retrying hash extraction with rar2john.exe...");
                    hashInfo = await HashFormatDetector.ExtractHashWithRetryAsync(
                        txtFilePath.Text,
                        maxRetries: 2,
                        onRetry: (attempt, max, error) => GpuLog($"   Retry {attempt}/{max}..."));
                }
                else
                {
                    GpuLog("⚠️ Failed to get rar2john.exe - cannot extract hash from RAR");
                }
            }

            // Check if hash extraction failed
            if (!hashInfo.IsValid)
            {
                // For 7-Zip, try using john.exe directly instead of hashcat
                if (hashInfo.Type == HashFormatDetector.HashType.SevenZip && File.Exists(JohnExePath))
                {
                    GpuLog("⚠️ Hash extraction failed, switching to John the Ripper for 7z cracking...");
                    // Determine attack type: use dictionary if available, otherwise brute force
                    string johnAttackType = (!string.IsNullOrEmpty(_dictionaryPath) && File.Exists(_dictionaryPath))
                        ? "dictionary"
                        : "bruteforce";
                    await RunJohnCrackingAsync(txtFilePath.Text, johnAttackType);
                    return;
                }

                GpuLog($"❌ ERROR: Could not extract hash");
                GpuLog($"   Type: {hashInfo.Type}");
                GpuLog($"   Message: {hashInfo.ErrorMessage}");
                GpuLog("");
                if (hashInfo.Type == HashFormatDetector.HashType.SevenZip)
                {
                    if (File.Exists(JohnExePath))
                    {
                        GpuLog("💡 Try using John the Ripper directly (john.exe) for this 7z file.");
                    }
                    else
                    {
                        GpuLog("💡 7z2john requires Perl with Compress::Raw::Lzma module.");
                        GpuLog("   Install full Strawberry Perl from: https://strawberryperl.com/");
                    }
                }
                else if (hashInfo.Type == HashFormatDetector.HashType.RAR3 || hashInfo.Type == HashFormatDetector.HashType.RAR5)
                {
                    GpuLog("💡 Try enabling GPU mode to auto-download John the Ripper (includes rar2john.exe)");
                }
                else
                {
                    GpuLog("💡 Tip: For RAR and 7-Zip files, you may need external tools:");
                    GpuLog("   - RAR: Use 'rar2john.exe' (auto-downloaded from John the Ripper)");
                    GpuLog("   - 7z:  Use '7z2john.pl' (requires Perl)");
                }
                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Hash Error");
                return;
            }

            // Check if hash string is available
            if (hashInfo.Hash == null)
            {
                GpuLog($"❌ ERROR: Hash extraction not supported for this format");
                GpuLog($"   Type: {hashInfo.Type}");
                GpuLog($"   Mode: {hashInfo.HashcatMode}");
                if (!string.IsNullOrEmpty(hashInfo.ErrorMessage))
                {
                    GpuLog($"   {hashInfo.ErrorMessage}");
                }
                GpuLog("");
                GpuLog("💡 GPU mode is not available for this archive type.");
                GpuLog("   Please use CPU mode or extract hash manually.");
                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Not Supported");
                return;
            }

            GpuLog($"✓ Detected: {hashInfo.Type}");
            GpuLog($"  Hashcat Mode: {hashInfo.HashcatMode} ({HashFormatDetector.GetHashcatModeDescription(hashInfo.HashcatMode)})");
            GpuLog($"  Hash extracted successfully");

            // Write hash to temp file
            string hashFile = Path.Combine(Path.GetTempPath(), $"archive_hash_{Guid.NewGuid():N}.txt");
            File.WriteAllText(hashFile, hashInfo.Hash);

            // Update hash preview in GPU panel
            Dispatcher.BeginInvoke(() =>
            {
                // Show truncated hash preview (first 60 chars)
                string hashPreview = hashInfo.Hash.Length > 60
                    ? hashInfo.Hash.Substring(0, 60) + "..."
                    : hashInfo.Hash;
                lblGpuHashPreview.Text = hashPreview;
                lblGpuHashPreview.Foreground = new SolidColorBrush(Color.FromRgb(255, 107, 53)); // Orange
            });

            // Log full hash for debugging (important for troubleshooting)
            GpuLog($"  Hash: {hashInfo.Hash}");
            GpuLog($"  Saved to: {hashFile}");

            GpuLog("");
            GpuLog("=== GPU ATTACK (Hashcat) ===");

            _gpuCts = new CancellationTokenSource();
            _gpuSpeed = 0;

            Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Starting...");

            // Build hashcat command based on selected checkboxes
            int minLen = int.Parse(txtMinLen.Text);
            int maxLen = int.Parse(txtMaxLen.Text);

            // Build custom charset from checkboxes for hashcat
            bool hasNumbers = chkNumbers?.IsChecked == true;
            bool hasLower = chkLowercase?.IsChecked == true;
            bool hasUpper = chkUppercase?.IsChecked == true;
            bool hasSpecial = chkSpecial?.IsChecked == true;

            string mask = "";
            string attackArgs = "";

            // Build hashcat custom charset based on selected options
            // In HYBRID mode (CPU+GPU), GPU does FULL brute force (CPU does dictionary)
            var hashcatCharset = new StringBuilder();
            bool isHybrid = _engine.IsHybridMode;

            if (isHybrid)
            {
                // Hybrid mode: GPU does FULL brute force (CPU does dictionary separately)
                GpuLog("=== HYBRID MODE: GPU doing full brute force ===");
                if (hasNumbers) hashcatCharset.Append("?d");
                if (hasLower) hashcatCharset.Append("?l");
                if (hasUpper) hashcatCharset.Append("?u");
                if (hasSpecial) hashcatCharset.Append("?s");

                // Update GPU pattern display
                Dispatcher.BeginInvoke(() =>
                {
                    string patternDesc = "Full: ";
                    if (hasNumbers) patternDesc += "0-9 ";
                    if (hasLower) patternDesc += "a-z ";
                    if (hasUpper) patternDesc += "A-Z ";
                    if (hasSpecial) patternDesc += "!@#$ ";
                    lblGpuPattern.Text = patternDesc.Trim();
                    if (_workManager != null)
                        _workManager.GpuStats.CurrentPattern = patternDesc.Trim();
                });
            }
            else
            {
                // Solo GPU mode: test everything
                if (hasNumbers) hashcatCharset.Append("?d");
                if (hasLower) hashcatCharset.Append("?l");
                if (hasUpper) hashcatCharset.Append("?u");
                if (hasSpecial) hashcatCharset.Append("?s");

                // Update GPU pattern display
                Dispatcher.BeginInvoke(() =>
                {
                    string patternDesc = "";
                    if (hasNumbers) patternDesc += "0-9 ";
                    if (hasLower) patternDesc += "a-z ";
                    if (hasUpper) patternDesc += "A-Z ";
                    if (hasSpecial) patternDesc += "!@#$ ";
                    lblGpuPattern.Text = patternDesc.Trim();
                    if (_workManager != null)
                        _workManager.GpuStats.CurrentPattern = patternDesc.Trim();
                });
            }

            if (hashcatCharset.Length == 0)
            {
                GpuLog("ERROR: No charset selected!");
                return;
            }

            string charsetDef = hashcatCharset.ToString();

            // Build attack phases based on selected strategy
            var attackPhases = BuildAttackPhases(_selectedStrategy, hasNumbers, hasLower, hasUpper, hasSpecial, minLen, maxLen, charsetDef);

            if (attackPhases.Count == 0)
            {
                string singleMask = string.Concat(System.Linq.Enumerable.Repeat("?1", maxLen));
                attackPhases.Add(($"Selected charset ({charsetDef})", charsetDef, singleMask, minLen, maxLen));
            }

            // Use the auto-detected hashcat mode from HashFormatDetector
            string hashcatMode = hashInfo.HashcatMode.ToString();

            // Get strategy name for display
            string strategyName = _selectedStrategy switch
            {
                AttackStrategy.LengthFirst => "🚀 LENGTH-FIRST",
                AttackStrategy.PatternFirst => "🎯 PATTERN-FIRST",
                AttackStrategy.SmartMix => "🔀 SMART MIX",
                AttackStrategy.CommonFirst => "⭐ COMMON-FIRST",
                _ => "PROGRESSIVE"
            };

            GpuLog($"=== {strategyName} ATTACK ({attackPhases.Count} phases) ===");
            for (int i = 0; i < attackPhases.Count; i++)
            {
                GpuLog($"  Phase {i + 1}: {attackPhases[i].name} (len {attackPhases[i].minLen}-{attackPhases[i].maxLen})");
            }
            GpuLog("");

            // Track total phases for progress display
            _totalGpuPhases = attackPhases.Count;

            // If resuming, use saved phase info; otherwise start from 0
            int startPhase = 0;
            if (_resumeFromGpuPhase > 0 && _resumeTotalGpuPhases == attackPhases.Count)
            {
                // Resume from saved phase (1-indexed, so subtract 1 for array index)
                startPhase = _resumeFromGpuPhase - 1;
                GpuLog($"[RESUME] Skipping to phase {_resumeFromGpuPhase}/{attackPhases.Count}");
                // Clear resume state
                _resumeFromGpuPhase = 0;
                _resumeTotalGpuPhases = 0;
            }
            else
            {
                _currentGpuPhase = 0;
            }

            // Run each attack phase sequentially until password found or all exhausted
            int currentPhase = startPhase;
            foreach (var phase in attackPhases.Skip(startPhase))
            {
                currentPhase++;
                _currentGpuPhase = currentPhase;
                _gpuProgress = 0; // Reset phase progress เมื่อเริ่ม phase ใหม่

                if (_passwordFound || _gpuCts.Token.IsCancellationRequested)
                    break;

                GpuLog($"");
                GpuLog($"══════════════════════════════════════════════════");
                GpuLog($"  PHASE {currentPhase}/{attackPhases.Count}: {phase.name}");
                GpuLog($"  Length: {phase.minLen} - {phase.maxLen}");
                GpuLog($"══════════════════════════════════════════════════");

                // Update UI - แสดง phase info และ reset progress bar
                Dispatcher.BeginInvoke(() =>
                {
                    lblGpuPattern.Text = $"Phase {currentPhase}: {phase.name}";
                    lblGpuStatus.Text = $"Phase {currentPhase}/{attackPhases.Count}";
                    if (_workManager != null)
                        _workManager.GpuStats.CurrentPattern = $"Phase {currentPhase}: {phase.name}";

                    // Reset phase progress bar
                    gpuPhaseProgressFill.Width = 0;
                    lblGpuPhasePercent.Text = "0%";
                });

                string outputFile = Path.Combine(Path.GetTempPath(), $"hashcat_found_{Guid.NewGuid():N}.txt");

                // Build mask for this phase's length
                string phaseMask = string.Concat(Enumerable.Repeat(
                    phase.charset == "?d" || phase.charset == "?l" || phase.charset == "?u" || phase.charset == "?s"
                        ? phase.charset : "?1",
                    phase.maxLen));

                // Build attack args for this phase
                string phaseAttackArgs;
                if (phase.charset == "?d" || phase.charset == "?l" || phase.charset == "?u" || phase.charset == "?s")
                {
                    // Single charset - use directly
                    phaseAttackArgs = $"-a 3 --increment --increment-min {phase.minLen} --increment-max {phase.maxLen}";
                }
                else
                {
                    // Multiple charsets - use custom charset -1
                    phaseAttackArgs = $"-a 3 -1 {phase.charset} --increment --increment-min {phase.minLen} --increment-max {phase.maxLen}";
                }

                // -w 3 = high workload (faster), -O = optimized kernels
                string args = $"-m {hashcatMode} {phaseAttackArgs} -w 3 -O -o \"{outputFile}\" --potfile-disable --status --status-timer=1 \"{hashFile}\" {phaseMask}";

                GpuLog($"Charset: {phase.charset}");
                GpuLog($"Command: hashcat {args}");
                GpuLog("");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = txtHashcatPath.Text,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true, // For pause/resume control
                    WorkingDirectory = Path.GetDirectoryName(txtHashcatPath.Text)
                };

                _hashcatProcess = new Process { StartInfo = psi };

                _hashcatProcess.OutputDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data) && !_passwordFound)
                    {
                        // Parse data on background thread first to minimize UI thread work
                        string data = e.Data;
                        long? parsedSpeed = null;
                        long? parsedTested = null;
                        double? parsedPercent = null;
                        int? parsedTemp = null;
                        string statusUpdate = null;

                        // Parse speed from hashcat output
                        if (data.Contains("Speed."))
                        {
                            var match = Regex.Match(data, @"(\d+\.?\d*)\s*(k|M|G)?H/s");
                            if (match.Success)
                            {
                                double speed = double.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                                string unit = match.Groups[2].Value;
                                if (unit == "k") speed *= 1000;
                                else if (unit == "M") speed *= 1000000;
                                else if (unit == "G") speed *= 1000000000;
                                parsedSpeed = (long)speed;
                            }
                        }

                        // Parse progress from hashcat output
                        if (data.Contains("Progress"))
                        {
                            var match = Regex.Match(data, @"Progress[.\s]*:\s*(\d+)/(\d+)\s*\((\d+\.?\d*)%\)");
                            if (match.Success)
                            {
                                parsedTested = long.Parse(match.Groups[1].Value);
                                parsedPercent = double.Parse(match.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture);
                            }
                        }

                        // Parse GPU temperature
                        if (data.Contains("Temp") && (data.Contains("c") || data.Contains("°")))
                        {
                            var match = Regex.Match(data, @"Temp[.\s:]*(\d+)\s*[c°]", RegexOptions.IgnoreCase);
                            if (match.Success)
                            {
                                parsedTemp = int.Parse(match.Groups[1].Value);
                            }
                        }

                        // Parse status
                        if (data.Contains("Status.."))
                        {
                            if (data.Contains("Exhausted")) statusUpdate = "Exhausted";
                            else if (data.Contains("Cracked")) statusUpdate = "Cracked!";
                        }

                        // Update UI asynchronously with parsed values
                        Dispatcher.BeginInvoke(() =>
                        {
                            GpuLog(data);

                            if (parsedSpeed.HasValue)
                            {
                                _gpuSpeed = parsedSpeed.Value;
                                lblGpuSpeed.Text = $"{_gpuSpeed:N0} /sec";
                            }

                            if (parsedTested.HasValue && parsedPercent.HasValue)
                            {
                                _gpuTestedCount = parsedTested.Value;
                                _gpuProgress = parsedPercent.Value; // Keep as double for accurate progress
                                lblGpuStatus.Text = $"Running ({parsedPercent.Value:F1}%)";
                            }

                            if (parsedTemp.HasValue)
                            {
                                _gpuTemp = parsedTemp.Value;
                            }

                            if (statusUpdate != null)
                            {
                                lblGpuStatus.Text = statusUpdate;
                            }
                        });
                    }
                };

                _hashcatProcess.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data) && !_passwordFound)
                    {
                        Dispatcher.BeginInvoke(() => GpuLog($"[ERR] {e.Data}"));
                    }
                };

                GpuLog("Starting hashcat process...");
                GpuLog($"Executable: {txtHashcatPath.Text}");

                _hashcatProcess.Start();
                GpuLog($"Hashcat PID: {_hashcatProcess.Id}");

                // Register with watchdog for crash detection
                WatchdogService.Instance.RegisterHashcatProcess(_hashcatProcess);
                WatchdogService.Instance.SetCurrentArchive(txtFilePath.Text);

                _hashcatProcess.BeginOutputReadLine();
                _hashcatProcess.BeginErrorReadLine();

                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Compiling kernels...");

                await Task.Run(() =>
                {
                    int checkCount = 0;
                    while (!_hashcatProcess.HasExited && !_gpuCts.Token.IsCancellationRequested && !_passwordFound)
                    {
                        Thread.Sleep(500);
                        checkCount++;

                        // Log check status every 10 checks (5 seconds)
                        if (checkCount % 10 == 0)
                        {
                            Dispatcher.BeginInvoke(() => GpuLog($"[DEBUG] Checking output file... (check #{checkCount})"));
                        }

                        // Check if password was found
                        if (File.Exists(outputFile) && new FileInfo(outputFile).Length > 0)
                        {
                            string result = File.ReadAllText(outputFile).Trim();
                            Dispatcher.BeginInvoke(() => GpuLog($"[DEBUG] Output file content: {result}"));

                            if (!string.IsNullOrEmpty(result))
                            {
                                // Parse password from hash:password format
                                // Format varies by hash type:
                                // - WinZip: $zip2$...*$/zip2$:password
                                // - 7-Zip: $7z$...$...:password
                                // - PKZIP: $pkzip$...:password
                                // Always use LastIndexOf(':') to get the password after the last colon
                                int colonIdx = result.LastIndexOf(':');

                                if (colonIdx > 0 && colonIdx < result.Length - 1)
                                {
                                    string foundPwd = result.Substring(colonIdx + 1);

                                    // Password found by GPU!
                                    _passwordFound = true;
                                    _foundPassword = foundPwd;

                                    // Cancel CPU
                                    _masterCts?.Cancel();
                                    _engine.Stop();

                                    Dispatcher.BeginInvoke(() =>
                                    {
                                        GpuLog("");
                                        GpuLog("========================================");
                                        GpuLog($"PASSWORD FOUND: {foundPwd}");
                                        GpuLog("========================================");

                                        HandlePasswordFound(foundPwd, "GPU");
                                    });

                                    try { _hashcatProcess.Kill(); } catch { }
                                    break;
                                }
                            }
                        }
                    }
                });

                if (!_hashcatProcess.HasExited)
                {
                    try { _hashcatProcess.Kill(); } catch { }
                }
                _hashcatProcess.WaitForExit(5000);

                // Unregister from watchdog
                WatchdogService.Instance.UnregisterHashcatProcess();

                // Wait a bit for output file to be written completely
                await Task.Delay(200);

                // FIRST: Check if password was found in output file BEFORE checking exit code
                // This is important because hashcat may exit with -1 when killed after finding password
                if (!_passwordFound && File.Exists(outputFile) && new FileInfo(outputFile).Length > 0)
                {
                    string earlyResult = File.ReadAllText(outputFile).Trim();
                    int earlyColonIdx = earlyResult.LastIndexOf(':');
                    if (earlyColonIdx > 0 && earlyColonIdx < earlyResult.Length - 1)
                    {
                        string foundPwd = earlyResult.Substring(earlyColonIdx + 1);
                        if (!string.IsNullOrEmpty(foundPwd))
                        {
                            GpuLog($"");
                            GpuLog($"========================================");
                            GpuLog($"[GPU] CANDIDATE PASSWORD: {foundPwd}");
                            GpuLog($"========================================");

                            // Try to handle - this will verify the password
                            _passwordFound = true;
                            _foundPassword = foundPwd;
                            HandlePasswordFound(foundPwd, "GPU");

                            // Check if password was actually valid (HandlePasswordFound resets _passwordFound if invalid)
                            if (_passwordFound)
                            {
                                break; // Exit phase loop - password verified!
                            }
                            else
                            {
                                // Password was a false positive - continue to next phase
                                GpuLog($"[GPU] Password '{foundPwd}' failed verification - continuing...");
                            }
                        }
                    }
                }

                // Log exit code for debugging
                int exitCode = _hashcatProcess.ExitCode;
                GpuLog($"");
                GpuLog($"========================================");
                GpuLog($"[GPU] Hashcat exit code: {exitCode}");
                GpuLog($"========================================");

                // Hashcat exit codes:
                // 0 = cracked successfully
                // 1 = exhausted (all passwords tried, no match found)
                // -1 = error (internal error)
                // -2 = abort by user
                // 255 = error (other)
                // Skip exit code processing if password was already found and verified
                if (_passwordFound)
                {
                    GpuLog($"[GPU] Password already verified - skipping exit code processing");
                    break; // Exit phase loop
                }

                switch (exitCode)
                {
                    case 0:
                        GpuLog("[GPU] Status: Hashcat reports CRACKED");
                        // Password should have been handled above, but double-check
                        if (!_passwordFound)
                        {
                            GpuLog("[GPU] WARNING: Exit code 0 but password not processed - this shouldn't happen");
                        }
                        break;
                    case 1:
                        GpuLog("[GPU] Status: EXHAUSTED - All passwords tried, no match found");
                        GpuLog("[GPU] This means the password is NOT in the tested range/charset");
                        break;
                    case -1:
                    case 255:
                        // Password should have been checked above already
                        // Just log the error status (common when hashcat is killed)
                        GpuLog("[GPU] Status: Hashcat exited with error code (may be normal if killed)");
                        break;
                    default:
                        GpuLog($"[GPU] Status: Unknown exit code {exitCode}");
                        break;
                }

                if (!_passwordFound)
                {
                    // Accumulate tested count from this phase to total
                    _gpuTotalTestedCount += _gpuTestedCount;
                    GpuLog($"[GPU] Phase {currentPhase} tested: {_gpuTestedCount:N0}, Total accumulated: {_gpuTotalTestedCount:N0}");

                    if (exitCode == 1)
                    {
                        GpuLog($"[GPU] Phase {currentPhase} exhausted - moving to next phase...");
                        Dispatcher.BeginInvoke(() => lblGpuStatus.Text = $"Phase {currentPhase} done");
                    }
                    else if (exitCode == 0)
                    {
                        GpuLog("[GPU] Hashcat reports cracked but password not extracted?");
                    }
                    else
                    {
                        GpuLog($"[GPU] Phase {currentPhase} error - exit code {exitCode}");
                    }

                    // Reset phase tested count for next phase
                    _gpuTestedCount = 0;
                }

                // Clean up this phase's output file
                try { File.Delete(outputFile); } catch { }

            } // end try
            catch (Exception ex)
            {
                GpuLog($"[ERROR] Phase {currentPhase}: {ex.Message}");
            }

            } // end foreach phase

            // All phases completed
            if (!_passwordFound)
            {
                GpuLog("");
                GpuLog("═══════════════════════════════════════════════════");
                GpuLog("  ALL PHASES COMPLETED - PASSWORD NOT FOUND");
                GpuLog("═══════════════════════════════════════════════════");
                GpuLog("[GPU] Tried all charset combinations without success.");
                GpuLog("[GPU] Consider:");
                GpuLog("   - Increasing max password length");
                GpuLog("   - Using dictionary attack");
                GpuLog("   - The password may use characters not selected");
                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Not found");
            }

            // Cleanup
            _gpuSpeed = 0;
            try { File.Delete(hashFile); } catch { }
        }

        private void Log(string message)
        {
            txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            txtLog.CaretIndex = txtLog.Text.Length;
            txtLog.ScrollToEnd();
        }

        private void UpdateTemperatureDisplay()
        {
            try
            {
                // Update CPU temperature
                int cpuTemp = GetCpuTemperature();
                if (cpuTemp > 0)
                {
                    _cpuTemp = cpuTemp;
                    lblCpuTemp.Text = $"{cpuTemp}°C";

                    // Update bar width (max 100°C = full width)
                    double barWidth = Math.Min(cpuTemp / 100.0, 1.0) * (cpuTempBar.Parent as FrameworkElement).ActualWidth;
                    cpuTempBar.Width = Math.Max(barWidth, 0);

                    // Change color based on temperature
                    if (cpuTemp >= 85)
                        cpuTempBar.Background = new SolidColorBrush(Color.FromRgb(255, 50, 50)); // Red - Hot!
                    else if (cpuTemp >= 70)
                        cpuTempBar.Background = new SolidColorBrush(Color.FromRgb(255, 165, 0)); // Orange - Warm
                    else
                        cpuTempBar.Background = new SolidColorBrush(Color.FromRgb(0, 255, 136)); // Green - Cool
                }

                // Update GPU temperature
                if (_gpuTemp > 0)
                {
                    lblGpuTemp.Text = $"{_gpuTemp}°C";

                    // Update bar width
                    double barWidth = Math.Min(_gpuTemp / 100.0, 1.0) * (gpuTempBar.Parent as FrameworkElement).ActualWidth;
                    gpuTempBar.Width = Math.Max(barWidth, 0);

                    // Change color based on temperature
                    if (_gpuTemp >= 85)
                        gpuTempBar.Background = new SolidColorBrush(Color.FromRgb(255, 50, 50)); // Red - Hot!
                    else if (_gpuTemp >= 70)
                        gpuTempBar.Background = new SolidColorBrush(Color.FromRgb(255, 165, 0)); // Orange - Warm
                    else
                        gpuTempBar.Background = new SolidColorBrush(Color.FromRgb(255, 107, 53)); // Normal GPU color
                }
            }
            catch { }
        }

        private int GetCpuTemperature()
        {
            try
            {
                // Try WMI first (works on some systems)
                using var searcher = new ManagementObjectSearcher(@"root\WMI", "SELECT * FROM MSAcpi_ThermalZoneTemperature");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var temp = Convert.ToDouble(obj["CurrentTemperature"]);
                    // WMI returns temperature in tenths of Kelvin
                    int celsius = (int)((temp - 2732) / 10.0);
                    if (celsius > 0 && celsius < 150)
                        return celsius;
                }
            }
            catch { }

            try
            {
                // Try alternative WMI path
                using var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var temp = Convert.ToDouble(obj["Temperature"]);
                    int celsius = (int)(temp - 273.15);
                    if (celsius > 0 && celsius < 150)
                        return celsius;
                }
            }
            catch { }

            // Return simulated temp based on CPU usage if WMI fails
            try
            {
                // Estimate based on process CPU - not accurate but gives visual feedback
                var process = Process.GetCurrentProcess();
                double cpuPercent = process.TotalProcessorTime.TotalMilliseconds / (Environment.ProcessorCount * _stopwatch.Elapsed.TotalMilliseconds) * 100;
                cpuPercent = Math.Min(cpuPercent, 100);

                // Simulate temp: idle=35°C, full load=80°C
                return (int)(35 + (cpuPercent / 100.0) * 45);
            }
            catch
            {
                return 0;
            }
        }

        private void GpuLog(string message)
        {
            if (Dispatcher.CheckAccess())
            {
                // Fade logo when GPU starts logging (still visible as shadow)
                if (imgGpuLogo.Opacity > 0.05)
                {
                    imgGpuLogo.Opacity = 0.05; // Very faint shadow
                }

                txtGpuLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                txtGpuLog.CaretIndex = txtGpuLog.Text.Length;
                txtGpuLog.ScrollToEnd();
            }
            else
            {
                Dispatcher.BeginInvoke(() =>
                {
                    // Fade logo when GPU starts logging (still visible as shadow)
                    if (imgGpuLogo.Opacity > 0.05)
                    {
                        imgGpuLogo.Opacity = 0.05; // Very faint shadow
                    }

                    txtGpuLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                    txtGpuLog.CaretIndex = txtGpuLog.Text.Length;
                    txtGpuLog.ScrollToEnd();
                });
            }
        }

        /// <summary>
        /// System/Notification log (blue panel)
        /// </summary>
        private void SystemLog(string message)
        {
            if (Dispatcher.CheckAccess())
            {
                txtSystemLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                txtSystemLog.CaretIndex = txtSystemLog.Text.Length;
                txtSystemLog.ScrollToEnd();
            }
            else
            {
                Dispatcher.BeginInvoke(() =>
                {
                    txtSystemLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                    txtSystemLog.CaretIndex = txtSystemLog.Text.Length;
                    txtSystemLog.ScrollToEnd();
                });
            }
        }

        /// <summary>
        /// Run John the Ripper directly for 7z/RAR files when hashcat cannot extract hash
        /// </summary>
        private async Task RunJohnCrackingAsync(string archivePath, string attackType)
        {
            try
            {
                // Initialize cancellation token if not already set
                _gpuCts ??= new CancellationTokenSource();

                GpuLog("=== JOHN THE RIPPER MODE ===");
                GpuLog($"Archive: {Path.GetFileName(archivePath)}");

                // Find best john.exe version
                string johnExe = JohnExePath;
                if (!File.Exists(johnExe))
                {
                    // Try to find any john executable
                    var johnExes = Directory.GetFiles(JohnRunDir, "john*.exe", SearchOption.TopDirectoryOnly)
                        .Where(f => !f.Contains("2john"))
                        .OrderByDescending(f => f.Contains("avx2"))
                        .ThenByDescending(f => f.Contains("avx"))
                        .ToList();

                    if (johnExes.Count > 0)
                        johnExe = johnExes[0];
                    else
                    {
                        GpuLog("❌ john.exe not found in John the Ripper folder");
                        return;
                    }
                }

                GpuLog($"Using: {Path.GetFileName(johnExe)}");

                // First, extract hash using 7z2john.pl if available
                string hashFile = null;
                string ext = Path.GetExtension(archivePath).ToLowerInvariant();

                if (ext == ".7z")
                {
                    // Try to use 7z2john.pl to extract hash first
                    string sevenZ2JohnExe = Path.Combine(JohnRunDir, "7z2john.pl");
                    if (File.Exists(sevenZ2JohnExe) && !string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath))
                    {
                        GpuLog("Extracting hash with 7z2john.pl...");
                        hashFile = Path.Combine(Path.GetTempPath(), $"7z_hash_{Guid.NewGuid():N}.txt");

                        var extractPsi = new ProcessStartInfo
                        {
                            FileName = _perlPath,
                            Arguments = $"\"{sevenZ2JohnExe}\" \"{archivePath}\"",
                            WorkingDirectory = JohnRunDir,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };

                        // Set Strawberry Perl environment if using system Perl
                        if (_perlPath.Contains("Strawberry"))
                        {
                            string strawberryRoot = @"C:\Strawberry";
                            string currentPath = Environment.GetEnvironmentVariable("PATH") ?? "";
                            string newPath = $@"{strawberryRoot}\c\bin;{strawberryRoot}\perl\bin;{strawberryRoot}\perl\site\bin;{currentPath}";
                            extractPsi.Environment["PATH"] = newPath;
                            extractPsi.Environment["PERL5LIB"] = $@"{strawberryRoot}\perl\lib;{strawberryRoot}\perl\site\lib;{strawberryRoot}\perl\vendor\lib";
                        }

                        try
                        {
                            using var extractProcess = Process.Start(extractPsi);
                            string output = await extractProcess.StandardOutput.ReadToEndAsync();
                            string error = await extractProcess.StandardError.ReadToEndAsync();
                            await Task.Run(() => extractProcess.WaitForExit(30000));

                            if (!string.IsNullOrEmpty(output) && output.Contains("$7z$"))
                            {
                                File.WriteAllText(hashFile, output.Trim());
                                GpuLog($"Hash extracted successfully");
                            }
                            else
                            {
                                // Check for specific DLL loading error - need full Perl
                                if (error.Contains("Lzma") || error.Contains("Can't load"))
                                {
                                    GpuLog("⚠️ Portable Perl missing Compress::Raw::Lzma module");
                                    GpuLog("Downloading full Strawberry Perl (~150MB)...");

                                    // Download and install full Perl
                                    await DownloadStrawberryPerlAsync();

                                    // Retry with new Perl - need to set up proper environment
                                    if (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath) && _perlPath.Contains("Strawberry"))
                                    {
                                        GpuLog("Retrying with full Strawberry Perl...");

                                        // Create new ProcessStartInfo with Strawberry environment
                                        var retryPsi = new ProcessStartInfo
                                        {
                                            FileName = _perlPath,
                                            Arguments = $"\"{sevenZ2JohnExe}\" \"{archivePath}\"",
                                            WorkingDirectory = JohnRunDir,
                                            UseShellExecute = false,
                                            CreateNoWindow = true,
                                            RedirectStandardOutput = true,
                                            RedirectStandardError = true
                                        };

                                        // Set Strawberry Perl environment variables - liblzma-5__.dll is in c\bin
                                        string strawberryRoot = @"C:\Strawberry";
                                        string currentPath = Environment.GetEnvironmentVariable("PATH") ?? "";
                                        // c\bin contains liblzma-5__.dll which is required by Lzma.xs.dll
                                        string newPath = $@"{strawberryRoot}\c\bin;{strawberryRoot}\perl\bin;{strawberryRoot}\perl\site\bin;{strawberryRoot}\perl\vendor\bin;{currentPath}";
                                        retryPsi.Environment["PATH"] = newPath;
                                        retryPsi.Environment["PERL5LIB"] = $@"{strawberryRoot}\perl\lib;{strawberryRoot}\perl\site\lib;{strawberryRoot}\perl\vendor\lib";

                                        using var retryProcess = Process.Start(retryPsi);
                                        output = await retryProcess.StandardOutput.ReadToEndAsync();
                                        error = await retryProcess.StandardError.ReadToEndAsync();
                                        await Task.Run(() => retryProcess.WaitForExit(30000));

                                        if (!string.IsNullOrEmpty(output) && output.Contains("$7z$"))
                                        {
                                            File.WriteAllText(hashFile, output.Trim());
                                            GpuLog($"✅ Hash extracted successfully with full Perl!");
                                        }
                                        else
                                        {
                                            GpuLog($"Still failed: {error}");
                                            hashFile = null;
                                        }
                                    }
                                    else
                                    {
                                        hashFile = null;
                                    }
                                }
                                else if (!string.IsNullOrEmpty(error))
                                {
                                    GpuLog($"7z2john error: {error}");
                                    hashFile = null;
                                }
                                else
                                {
                                    GpuLog("7z2john produced no output");
                                    hashFile = null;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            GpuLog($"7z2john error: {ex.Message}");
                            hashFile = null;
                        }
                    }

                    if (hashFile == null)
                    {
                        GpuLog("❌ Cannot extract 7z hash - Perl with Compress::Raw::Lzma module required");
                        GpuLog("💡 Install full Strawberry Perl from: https://strawberryperl.com/");
                        GpuLog("   Then run: cpan install Compress::Raw::Lzma");
                        Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Perl Required");
                        return;
                    }
                }

                // Build john command arguments
                string args = "";
                string targetFile = hashFile ?? archivePath;

                if (attackType == "dictionary" && !string.IsNullOrEmpty(_dictionaryPath) && File.Exists(_dictionaryPath))
                {
                    args = $"--wordlist=\"{_dictionaryPath}\" \"{targetFile}\"";
                    GpuLog($"Attack: Dictionary ({Path.GetFileName(_dictionaryPath)})");
                }
                else
                {
                    // Incremental mode (brute force)
                    args = $"--incremental \"{targetFile}\"";
                    GpuLog($"Attack: Incremental (brute force)");
                }

                var psi = new ProcessStartInfo
                {
                    FileName = johnExe,
                    Arguments = args,
                    WorkingDirectory = JohnRunDir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "John running...");
                GpuLog("Starting John the Ripper...");

                using var process = Process.Start(psi);
                if (process == null)
                {
                    GpuLog("❌ Failed to start john.exe");
                    return;
                }

                // Read output
                process.OutputDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        string data = e.Data;
                        Dispatcher.BeginInvoke(() => GpuLog(data));

                        // Check for cracked password
                        if (data.Contains(":") && !data.StartsWith("Using") && !data.StartsWith("Loaded"))
                        {
                            var parts = data.Split(':');
                            if (parts.Length >= 2)
                            {
                                string password = parts[parts.Length - 1].Trim();
                                if (!string.IsNullOrEmpty(password) && password.Length < 50)
                                {
                                    Dispatcher.BeginInvoke(() =>
                                    {
                                        GpuLog($"🎉 PASSWORD FOUND: {password}");
                                        _passwordFound = true;
                                        HandlePasswordFound(password, "John the Ripper");
                                    });
                                }
                            }
                        }
                    }
                };

                process.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        string data = e.Data;
                        Dispatcher.BeginInvoke(() => GpuLog($"[INFO] {data}"));
                    }
                };

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await Task.Run(() =>
                {
                    while (!process.HasExited && !_gpuCts.Token.IsCancellationRequested && !_passwordFound)
                    {
                        Thread.Sleep(500);
                    }

                    if (!process.HasExited)
                    {
                        try { process.Kill(); } catch { }
                    }
                });

                if (_passwordFound)
                {
                    Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Found!");
                }
                else if (_gpuCts.Token.IsCancellationRequested)
                {
                    GpuLog("John the Ripper stopped by user.");
                    Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Stopped");
                }
                else
                {
                    GpuLog("John the Ripper finished - password not found in wordlist.");
                    Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Not found");
                }
            }
            catch (Exception ex)
            {
                GpuLog($"❌ John error: {ex.Message}");
                Dispatcher.BeginInvoke(() => lblGpuStatus.Text = "Error");
            }
        }

        /// <summary>
        /// Download all required tools on startup (runs in background)
        /// </summary>
        private async Task DownloadAllToolsOnStartupAsync()
        {
            await Task.Delay(500); // Small delay to let UI load first

            // Helper to log from any thread (non-blocking)
            void SafeLog(string msg)
            {
                Dispatcher.BeginInvoke(() => Log(msg));
            }

            SafeLog("🔧 Checking required tools...");

            int toolsDownloaded = 0;
            int toolsReady = 0;

            // 1. Check/Download Hashcat
            if (!File.Exists(HashcatExe))
            {
                SafeLog("   📥 Downloading Hashcat...");
                await CheckAndDownloadHashcatAsync();
                if (File.Exists(HashcatExe))
                {
                    toolsDownloaded++;
                    SafeLog("   ✅ Hashcat ready");
                }
            }
            else
            {
                toolsReady++;
            }

            // 2. Check/Download Wordlist (rockyou.txt)
            if (!File.Exists(RockyouPath))
            {
                SafeLog("   📥 Downloading wordlist (rockyou.txt)...");
                await CheckAndDownloadWordlistAsync();
                if (File.Exists(RockyouPath))
                {
                    toolsDownloaded++;
                    SafeLog("   ✅ Wordlist ready");
                }
            }
            else
            {
                toolsReady++;
                if (string.IsNullOrEmpty(_dictionaryPath))
                {
                    _dictionaryPath = RockyouPath;
                    Dispatcher.BeginInvoke(() => SaveSettings());
                }
            }

            // 3. Check/Download John the Ripper (contains rar2john.exe)
            bool hasRar2John = File.Exists(Rar2JohnPath) ||
                (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath));

            if (!hasRar2John)
            {
                SafeLog("   📥 Downloading John the Ripper (rar2john.exe)...");
                await DownloadRar2JohnAsync();
                if (File.Exists(Rar2JohnPath) || (!string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath)))
                {
                    if (string.IsNullOrEmpty(_rar2johnPath)) _rar2johnPath = Rar2JohnPath;
                    HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                    toolsDownloaded++;
                    SafeLog("   ✅ rar2john.exe ready");
                }
            }
            else
            {
                toolsReady++;
                if (string.IsNullOrEmpty(_rar2johnPath))
                {
                    _rar2johnPath = Rar2JohnPath;
                }
                HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                Dispatcher.BeginInvoke(() => SaveSettings());
            }

            // 4. Check 7z2john.pl (comes with John the Ripper package)
            bool has7z2John = File.Exists(SevenZ2JohnPath) ||
                (!string.IsNullOrEmpty(_7z2johnPath) && File.Exists(_7z2johnPath));

            if (has7z2John)
            {
                toolsReady++;
                if (string.IsNullOrEmpty(_7z2johnPath) || !File.Exists(_7z2johnPath))
                {
                    _7z2johnPath = SevenZ2JohnPath;
                }
                HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                SafeLog("   ✅ 7z2john.pl ready (from John the Ripper)");
            }
            else
            {
                // 7z2john.pl comes with John the Ripper, should be there if John was downloaded
                SafeLog("   ⚠️ 7z2john.pl not found (requires John the Ripper)");
            }

            // 5. Check/Download Perl (required for 7z2john.pl)
            bool hasPerl = File.Exists(PerlExe) ||
                (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath));

            if (!hasPerl)
            {
                SafeLog("   📥 Downloading Strawberry Perl...");
                await DownloadStrawberryPerlAsync();
                // _perlPath is set inside DownloadStrawberryPerlAsync
                if (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath))
                {
                    HashFormatDetector.SetPerlPath(_perlPath);
                    toolsDownloaded++;
                    SafeLog("   ✅ Perl ready");
                }
            }
            else
            {
                toolsReady++;
                // Find perl.exe if path not set
                if (string.IsNullOrEmpty(_perlPath) || !File.Exists(_perlPath))
                {
                    // Search for perl.exe
                    if (File.Exists(PerlExe))
                        _perlPath = PerlExe;
                    else if (Directory.Exists(PerlDir))
                    {
                        var found = Directory.GetFiles(PerlDir, "perl.exe", SearchOption.AllDirectories).FirstOrDefault();
                        if (found != null)
                            _perlPath = found;
                    }
                }
                if (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath))
                {
                    HashFormatDetector.SetPerlPath(_perlPath);
                    Dispatcher.BeginInvoke(() => SaveSettings());
                }
            }

            // Summary
            if (toolsDownloaded > 0)
            {
                SafeLog($"✅ Downloaded {toolsDownloaded} tool(s), {toolsReady + toolsDownloaded} total ready");
            }
            else if (toolsReady > 0)
            {
                SafeLog($"✅ All {toolsReady} tools already installed");
            }

            // Save all paths
            Dispatcher.BeginInvoke(() => SaveSettings());
        }

        private async Task CheckAndDownloadHashcatAsync()
        {
            // First check if user already declined download before
            string hashcatDeclined = _db?.GetSetting("hashcat_download_declined");
            if (hashcatDeclined == "true")
            {
                // User declined before, don't ask again
                return;
            }

            // First check common paths
            string[] possiblePaths = {
                HashcatExe,
                @"C:\hashcat\hashcat.exe",
                @"C:\Program Files\hashcat\hashcat.exe",
                @"D:\hashcat\hashcat.exe",
                Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\Downloads\hashcat-6.2.6\hashcat.exe")
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    Log($"Hashcat found: {path}");
                    Dispatcher.BeginInvoke(() =>
                    {
                        txtHashcatPath.Text = path;
                        chkGpu.IsChecked = true;
                    });

                    // Save to settings so we don't search again
                    _db?.SaveSetting("hashcat_path", path);
                    return;
                }
            }

            // Check if already downloaded before
            string savedPath = _db?.GetSetting("hashcat_path");
            if (!string.IsNullOrEmpty(savedPath) && File.Exists(savedPath))
            {
                Log($"Hashcat found: {savedPath}");
                Dispatcher.BeginInvoke(() =>
                {
                    txtHashcatPath.Text = savedPath;
                    chkGpu.IsChecked = true;
                });
                return;
            }

            // Hashcat not found - ask to download (only once)
            var result = MessageBox.Show(
                "Hashcat (GPU password cracker) is not installed.\n\n" +
                "Would you like to download and install it automatically?\n\n" +
                "This will enable GPU-accelerated password cracking which is much faster than CPU.\n\n" +
                "Download size: ~20 MB\n\n" +
                "(This message will only show once)",
                "Download Hashcat?",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                await DownloadHashcatAsync();
            }
            else
            {
                // Save that user declined
                _db?.SaveSetting("hashcat_download_declined", "true");
                Log("Hashcat download declined. You can install it later from Settings.");
                Log("Manual download: https://hashcat.net/hashcat/");
            }
        }

        private async Task DownloadHashcatAsync()
        {
            const string hashcatUrl = "https://hashcat.net/files/hashcat-6.2.6.7z";
            const string sevenZipUrl = "https://www.7-zip.org/a/7zr.exe";

            try
            {
                Log("");
                Log("=== DOWNLOADING HASHCAT ===");
                Log("Please wait, this may take a few minutes...");

                // Create directory
                Directory.CreateDirectory(HashcatDir);
                string downloadPath = Path.Combine(Path.GetTempPath(), "hashcat.7z");
                string sevenZipPath = Path.Combine(Path.GetTempPath(), "7zr.exe");

                // Download 7zr.exe first (to extract .7z files)
                if (!File.Exists(sevenZipPath))
                {
                    Log("Downloading 7-Zip extractor...");
                    var sevenZipData = await _httpClient.GetByteArrayAsync(sevenZipUrl);
                    await File.WriteAllBytesAsync(sevenZipPath, sevenZipData);
                    Log("7-Zip extractor downloaded.");
                }

                // Download Hashcat
                Log($"Downloading Hashcat from {hashcatUrl}...");
                Log("This is about 20 MB, please wait...");

                using (var response = await _httpClient.GetAsync(hashcatUrl, HttpCompletionOption.ResponseHeadersRead))
                {
                    response.EnsureSuccessStatusCode();
                    var totalBytes = response.Content.Headers.ContentLength ?? -1;

                    using (var stream = await response.Content.ReadAsStreamAsync())
                    using (var fileStream = new FileStream(downloadPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var buffer = new byte[8192];
                        long totalRead = 0;
                        int bytesRead;
                        int lastProgress = 0;

                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await fileStream.WriteAsync(buffer, 0, bytesRead);
                            totalRead += bytesRead;

                            if (totalBytes > 0)
                            {
                                int progress = (int)(totalRead * 100 / totalBytes);
                                if (progress != lastProgress && progress % 10 == 0)
                                {
                                    Dispatcher.BeginInvoke(() => Log($"Download progress: {progress}%"));
                                    lastProgress = progress;
                                }
                            }
                        }
                    }
                }

                Log("Download complete. Extracting...");

                // Extract using 7zr.exe
                var extractProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = sevenZipPath,
                        Arguments = $"x \"{downloadPath}\" -o\"{HashcatDir}\" -y",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    }
                };

                extractProcess.Start();
                await extractProcess.WaitForExitAsync();

                // Find hashcat.exe in extracted folder
                string[] searchPaths = {
                    Path.Combine(HashcatDir, "hashcat-6.2.6", "hashcat.exe"),
                    Path.Combine(HashcatDir, "hashcat.exe")
                };

                string foundPath = null;
                foreach (var path in searchPaths)
                {
                    if (File.Exists(path))
                    {
                        foundPath = path;
                        break;
                    }
                }

                // Also search recursively
                if (foundPath == null)
                {
                    var files = Directory.GetFiles(HashcatDir, "hashcat.exe", SearchOption.AllDirectories);
                    if (files.Length > 0)
                        foundPath = files[0];
                }

                if (foundPath != null)
                {
                    Log($"Hashcat installed successfully!");
                    Log($"Location: {foundPath}");

                    // Save path to database
                    _db?.SaveSetting("hashcat_path", foundPath);

                    Dispatcher.BeginInvoke(() =>
                    {
                        txtHashcatPath.Text = foundPath;
                        chkGpu.IsChecked = true;
                        SaveSettings();
                    });

                    // Cleanup download
                    try { File.Delete(downloadPath); } catch { }

                    Log("");
                    Log("GPU mode is now available!");
                }
                else
                {
                    Log("ERROR: Could not find hashcat.exe after extraction.");
                    Log($"Please manually extract and browse to hashcat.exe");
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR downloading Hashcat: {ex.Message}");
                Log("");
                Log("You can manually download from: https://hashcat.net/hashcat/");
                Log("Extract to C:\\hashcat\\ and restart the application.");
            }
        }

        /// <summary>
        /// Check and download rockyou.txt wordlist for dictionary attack
        /// </summary>
        private async Task CheckAndDownloadWordlistAsync()
        {
            // Check if rockyou.txt already exists
            if (File.Exists(RockyouPath))
            {
                _dictionaryPath = RockyouPath;
                SystemLog($"Wordlist found: {Path.GetFileName(RockyouPath)}");
                return;
            }

            // Check if user-specified dictionary exists
            if (!string.IsNullOrEmpty(_dictionaryPath) && File.Exists(_dictionaryPath))
            {
                SystemLog($"Using custom wordlist: {Path.GetFileName(_dictionaryPath)}");
                return;
            }

            // Check default path
            if (File.Exists(DefaultDictionaryPath))
            {
                _dictionaryPath = DefaultDictionaryPath;
                SystemLog($"Using default wordlist: {Path.GetFileName(DefaultDictionaryPath)}");
                return;
            }

            // Check if user already declined
            string wordlistDeclined = _db?.GetSetting("wordlist_download_declined");
            if (wordlistDeclined == "true")
            {
                return;
            }

            // Ask to download rockyou.txt
            var result = MessageBox.Show(
                "Rockyou.txt wordlist (14 million passwords) is not found.\n\n" +
                "Would you like to download it automatically?\n\n" +
                "This wordlist contains the most common passwords and is essential for dictionary attacks.\n\n" +
                "Download size: ~140 MB\n\n" +
                "(This message will only show once)",
                "Download Rockyou Wordlist?",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                await DownloadRockyouAsync();
            }
            else
            {
                _db?.SaveSetting("wordlist_download_declined", "true");
                SystemLog("Wordlist download declined. CPU dictionary attack will use built-in passwords.");
                SystemLog("You can download wordlists manually and set path in Settings.");
            }
        }

        /// <summary>
        /// Download rockyou.txt from GitHub
        /// </summary>
        private async Task DownloadRockyouAsync()
        {
            try
            {
                SystemLog("");
                SystemLog("=== DOWNLOADING ROCKYOU WORDLIST ===");
                SystemLog("14 million common passwords (~140 MB)");
                SystemLog("Please wait, this may take a few minutes...");

                // Create directory
                Directory.CreateDirectory(WordlistDir);

                // Download with progress
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10)); // 10 min timeout
                using (var response = await _httpClient.GetAsync(RockyouUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token))
                {
                    response.EnsureSuccessStatusCode();
                    var totalBytes = response.Content.Headers.ContentLength ?? -1;

                    using (var stream = await response.Content.ReadAsStreamAsync(cts.Token))
                    using (var fileStream = new FileStream(RockyouPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var buffer = new byte[81920]; // 80KB buffer
                        long totalRead = 0;
                        int bytesRead;
                        int lastProgress = 0;

                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token)) > 0)
                        {
                            await fileStream.WriteAsync(buffer, 0, bytesRead, cts.Token);
                            totalRead += bytesRead;

                            if (totalBytes > 0)
                            {
                                int progress = (int)(totalRead * 100 / totalBytes);
                                if (progress != lastProgress && progress % 10 == 0)
                                {
                                    SystemLog($"Download progress: {progress}% ({totalRead / 1048576:N0} MB)");
                                    lastProgress = progress;
                                }
                            }
                        }
                    }
                }

                // Verify download
                var fileInfo = new FileInfo(RockyouPath);
                if (fileInfo.Exists && fileInfo.Length > 100000000) // > 100 MB
                {
                    _dictionaryPath = RockyouPath;
                    SaveSettings();

                    SystemLog("");
                    SystemLog("=== DOWNLOAD COMPLETE ===");
                    SystemLog($"Wordlist: {RockyouPath}");
                    SystemLog($"Size: {fileInfo.Length / 1048576:N0} MB");
                    SystemLog("CPU dictionary attack is now ready!");
                }
                else
                {
                    SystemLog("ERROR: Download incomplete. Please try again.");
                    try { File.Delete(RockyouPath); } catch { }
                }
            }
            catch (TaskCanceledException)
            {
                SystemLog("ERROR: Download timeout. Please check your internet connection.");
                try { File.Delete(RockyouPath); } catch { }
            }
            catch (Exception ex)
            {
                SystemLog($"ERROR downloading wordlist: {ex.Message}");
                SystemLog("You can manually download from:");
                SystemLog("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt");
                try { File.Delete(RockyouPath); } catch { }
            }
        }

        private async Task Download7z2JohnAsync()
        {
            const string url = "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/7z2john.pl";

            try
            {
                GpuLog("Downloading 7z2john.pl from GitHub...");
                Directory.CreateDirectory(ToolsDir);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var response = await _httpClient.GetAsync(url, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    GpuLog($"❌ Failed to download - HTTP {response.StatusCode}");
                    return;
                }

                var content = await response.Content.ReadAsStringAsync(cts.Token);
                await File.WriteAllTextAsync(SevenZ2JohnPath, content, cts.Token);

                _7z2johnPath = SevenZ2JohnPath;
                HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                SaveSettings();

                GpuLog($"✅ 7z2john.pl downloaded successfully!");
            }
            catch (TaskCanceledException)
            {
                GpuLog($"❌ Download timeout (10s) - Check your internet connection");
            }
            catch (HttpRequestException ex)
            {
                GpuLog($"❌ Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                GpuLog($"❌ Download error: {ex.Message}");
            }
        }

        private async Task DownloadStrawberryPerlAsync()
        {
            // Strawberry Perl MSI installer (64-bit) - full version with all modules
            const string url = "https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit.msi";
            // Standard installation path
            const string systemPerlPath = @"C:\Strawberry\perl\bin\perl.exe";

            try
            {
                // Check if Strawberry Perl is already installed system-wide
                if (File.Exists(systemPerlPath))
                {
                    GpuLog("✅ Strawberry Perl already installed!");
                    _perlPath = systemPerlPath;
                    HashFormatDetector.SetPerlPath(_perlPath);
                    SaveSettings();
                    return;
                }

                GpuLog("Downloading Strawberry Perl Full Installer (64-bit, ~150MB)...");
                GpuLog("This includes all required modules for 7z2john.");
                GpuLog("Please wait 2-3 minutes...");
                Directory.CreateDirectory(ToolsDir);

                var msiPath = Path.Combine(ToolsDir, "strawberry-perl.msi");

                // Download MSI installer
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10)); // 10 min timeout for larger file
                var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    GpuLog($"❌ Failed to download - HTTP {response.StatusCode}");
                    return;
                }

                var totalBytes = response.Content.Headers.ContentLength ?? 0;
                var totalMB = totalBytes / (1024.0 * 1024.0);
                GpuLog($"   File size: {totalMB:F1} MB");

                // Save to file with progress
                using (var contentStream = await response.Content.ReadAsStreamAsync())
                using (var fileStream = new FileStream(msiPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920))
                {
                    var buffer = new byte[81920];
                    long downloadedBytes = 0;
                    int bytesRead;
                    int lastPercent = 0;

                    while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length, cts.Token)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, bytesRead, cts.Token);
                        downloadedBytes += bytesRead;

                        if (totalBytes > 0)
                        {
                            int percent = (int)(downloadedBytes * 100 / totalBytes);
                            if (percent >= lastPercent + 10) // Update every 10%
                            {
                                lastPercent = percent;
                                GpuLog($"   Downloaded: {percent}%");
                            }
                        }
                    }
                }

                GpuLog("Download complete. Installing Strawberry Perl (silent install)...");
                GpuLog("This may take 1-2 minutes...");

                // Silent install using msiexec
                var installPsi = new ProcessStartInfo
                {
                    FileName = "msiexec.exe",
                    Arguments = $"/i \"{msiPath}\" /quiet /qn /norestart INSTALLDIR=\"C:\\Strawberry\"",
                    UseShellExecute = true,
                    Verb = "runas", // Request admin privileges
                    CreateNoWindow = true
                };

                try
                {
                    using var installProcess = Process.Start(installPsi);
                    if (installProcess != null)
                    {
                        // Wait for installation to complete (max 5 minutes)
                        await Task.Run(() => installProcess.WaitForExit(300000));

                        if (installProcess.ExitCode == 0)
                        {
                            GpuLog("✅ Strawberry Perl installed successfully!");
                        }
                        else if (installProcess.ExitCode == 1602)
                        {
                            GpuLog("❌ Installation cancelled by user");
                            return;
                        }
                        else if (installProcess.ExitCode == 1603)
                        {
                            GpuLog("❌ Installation failed - try running as Administrator");
                            return;
                        }
                        else
                        {
                            GpuLog($"⚠️ Installer exited with code: {installProcess.ExitCode}");
                        }
                    }
                }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    // User cancelled UAC prompt
                    GpuLog("❌ Installation cancelled - Administrator permission required");
                    GpuLog("💡 Please run the application as Administrator and try again");
                    return;
                }

                // Clean up MSI file
                try { File.Delete(msiPath); } catch { }

                // Verify installation and set path
                if (File.Exists(systemPerlPath))
                {
                    _perlPath = systemPerlPath;
                    HashFormatDetector.SetPerlPath(_perlPath);
                    SaveSettings();
                    GpuLog($"   Location: {systemPerlPath}");
                    GpuLog("   Includes Compress::Raw::Lzma module for 7z support!");
                }
                else
                {
                    // Search for perl.exe in case of custom install location
                    string[] searchPaths = {
                        @"C:\Strawberry\perl\bin\perl.exe",
                        @"C:\Program Files\Strawberry\perl\bin\perl.exe",
                        @"C:\perl\bin\perl.exe"
                    };

                    string foundPath = searchPaths.FirstOrDefault(File.Exists);
                    if (foundPath != null)
                    {
                        _perlPath = foundPath;
                        HashFormatDetector.SetPerlPath(_perlPath);
                        SaveSettings();
                        GpuLog($"✅ Perl found at: {foundPath}");
                    }
                    else
                    {
                        GpuLog("⚠️ Installation completed but perl.exe not found");
                        GpuLog("   Please restart the application");
                    }
                }
            }
            catch (TaskCanceledException)
            {
                GpuLog($"❌ Download timeout (10min) - Check your internet connection");
            }
            catch (HttpRequestException ex)
            {
                GpuLog($"❌ Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                GpuLog($"❌ Download/Install error: {ex.Message}");
            }
        }

        private async Task DownloadRar2JohnAsync()
        {
            // Download John the Ripper package which contains rar2john.exe
            const string url = "https://github.com/openwall/john-packages/releases/download/v1.9.1-ce/winX64_1_JtR.zip";

            // Helper to log from any thread (non-blocking)
            void SafeLog(string msg)
            {
                if (Dispatcher.CheckAccess())
                    Log(msg);
                else
                    Dispatcher.BeginInvoke(() => Log(msg));
            }

            try
            {
                SafeLog("   Downloading John the Ripper (~30MB)...");
                Directory.CreateDirectory(ToolsDir);

                var downloadPath = Path.Combine(ToolsDir, "john.zip");

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    SafeLog($"   ❌ Failed to download - HTTP {response.StatusCode}");
                    return;
                }

                // Save to file with progress
                var totalBytes = response.Content.Headers.ContentLength ?? 0;
                using (var fileStream = new FileStream(downloadPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var contentStream = await response.Content.ReadAsStreamAsync(cts.Token))
                {
                    var buffer = new byte[81920];
                    var totalRead = 0L;
                    var bytesRead = 0;
                    var lastProgress = 0;

                    while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length, cts.Token)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, bytesRead, cts.Token);
                        totalRead += bytesRead;

                        if (totalBytes > 0)
                        {
                            var progress = (int)(totalRead * 100 / totalBytes);
                            if (progress >= lastProgress + 20) // Log every 20%
                            {
                                SafeLog($"   Download progress: {progress}%");
                                lastProgress = progress;
                            }
                        }
                    }
                }

                SafeLog("   Download complete. Extracting...");

                // Extract to john directory
                if (Directory.Exists(JohnDir))
                    Directory.Delete(JohnDir, true);

                System.IO.Compression.ZipFile.ExtractToDirectory(downloadPath, JohnDir);
                File.Delete(downloadPath);

                // Check if rar2john.exe exists
                if (File.Exists(Rar2JohnPath))
                {
                    _rar2johnPath = Rar2JohnPath;
                    HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                    Dispatcher.BeginInvoke(() => SaveSettings());

                    SafeLog($"   ✅ rar2john.exe installed!");
                }
                else
                {
                    // Try to find rar2john.exe in extracted folder
                    var foundExe = Directory.GetFiles(JohnDir, "rar2john.exe", SearchOption.AllDirectories).FirstOrDefault();
                    if (foundExe != null)
                    {
                        _rar2johnPath = foundExe;
                        HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                        Dispatcher.BeginInvoke(() => SaveSettings());
                        SafeLog($"   ✅ rar2john.exe installed!");
                    }
                    else
                    {
                        SafeLog("   ⚠️ John the Ripper extracted but rar2john.exe not found");
                    }
                }
            }
            catch (TaskCanceledException)
            {
                SafeLog($"   ❌ Download timeout (5min) - Check internet connection");
            }
            catch (HttpRequestException ex)
            {
                SafeLog($"   ❌ Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                SafeLog($"   ❌ Download error: {ex.Message}");
            }
        }

        private async Task DownloadPythonPortableAsync()
        {
            // Python 3.11.7 Embedded (64-bit) - ~10MB
            const string url = "https://www.python.org/ftp/python/3.11.7/python-3.11.7-embed-amd64.zip";

            try
            {
                GpuLog("Downloading Python Portable (64-bit, ~10MB)...");
                Directory.CreateDirectory(ToolsDir);

                var downloadPath = Path.Combine(ToolsDir, "python-portable.zip");

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    GpuLog($"❌ Failed to download - HTTP {response.StatusCode}");
                    return;
                }

                // Save to file
                using (var fileStream = new FileStream(downloadPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await response.Content.CopyToAsync(fileStream, cts.Token);
                }

                GpuLog("Download complete. Extracting Python...");

                // Extract
                System.IO.Compression.ZipFile.ExtractToDirectory(downloadPath, PythonDir, true);
                File.Delete(downloadPath);

                // Set Python path
                if (File.Exists(PythonExe))
                {
                    _pythonPath = PythonExe;
                    SaveSettings();
                    GpuLog($"✅ Python installed successfully!");
                    GpuLog($"   Location: {PythonExe}");
                }
                else
                {
                    GpuLog($"⚠️ Python extracted but python.exe not found at expected location");
                }
            }
            catch (TaskCanceledException)
            {
                GpuLog($"❌ Download timeout (2min) - Check your internet connection");
            }
            catch (HttpRequestException ex)
            {
                GpuLog($"❌ Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                GpuLog($"❌ Download/Extract error: {ex.Message}");
            }
        }

        private async Task<bool> Ensure7z2JohnAsync()
        {
            // Check if already exists
            if (!string.IsNullOrEmpty(_7z2johnPath) && File.Exists(_7z2johnPath))
                return true;

            if (File.Exists(SevenZ2JohnPath))
            {
                _7z2johnPath = SevenZ2JohnPath;
                HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                return true;
            }

            // Auto-download
            await Download7z2JohnAsync();
            return File.Exists(SevenZ2JohnPath);
        }

        private void LoadHardwareInfo()
        {
            try
            {
                // Get CPU info
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        string cpuName = obj["Name"]?.ToString() ?? "Unknown CPU";
                        // Clean up the name
                        cpuName = cpuName.Replace("(R)", "").Replace("(TM)", "").Replace("  ", " ").Trim();
                        Dispatcher.BeginInvoke(() =>
                        {
                            lblCpuModel.Text = cpuName;
                            lblCpuModel.ToolTip = cpuName;
                        });
                        Log($"💻 CPU: {cpuName}");
                        break; // Only show first CPU
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Could not detect CPU: {ex.Message}");
                Dispatcher.BeginInvoke(() => lblCpuModel.Text = "Unknown CPU");
            }

            try
            {
                // Get GPU info
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController"))
                {
                    var gpuList = new List<string>();
                    foreach (var obj in searcher.Get())
                    {
                        string gpuName = obj["Name"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(gpuName) &&
                            !gpuName.Contains("Microsoft") &&
                            !gpuName.Contains("Remote") &&
                            !gpuName.Contains("Virtual"))
                        {
                            gpuList.Add(gpuName);
                        }
                    }

                    if (gpuList.Count > 0)
                    {
                        string gpuText = gpuList.Count > 1 ? $"{gpuList[0]} (+{gpuList.Count - 1} more)" : gpuList[0];
                        Dispatcher.BeginInvoke(() =>
                        {
                            lblGpuModel.Text = gpuText;
                            lblGpuModel.ToolTip = string.Join("\n", gpuList);
                        });
                        foreach (var gpu in gpuList)
                        {
                            Log($"🎮 GPU: {gpu}");
                        }
                    }
                    else
                    {
                        Dispatcher.BeginInvoke(() => lblGpuModel.Text = "No GPU detected");
                        Log("🎮 GPU: No dedicated GPU detected");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Could not detect GPU: {ex.Message}");
                Dispatcher.BeginInvoke(() => lblGpuModel.Text = "Unknown GPU");
            }
        }

        #region Custom Title Bar

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                BtnMaximize_Click(sender, e);
            }
            else
            {
                DragMove();
            }
        }

        private void BtnSettings_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new SettingsWindow(txtHashcatPath.Text, true, _7z2johnPath, _perlPath, _dictionaryPath, _rar2johnPath);
            if (settingsWindow.ShowDialog() == true && settingsWindow.SettingsSaved)
            {
                txtHashcatPath.Text = settingsWindow.HashcatPath;

                // Update 7z2john path
                if (!string.IsNullOrEmpty(settingsWindow.SevenZ2JohnPath))
                {
                    _7z2johnPath = settingsWindow.SevenZ2JohnPath;
                    HashFormatDetector.Set7z2JohnPath(_7z2johnPath);
                    Log($"7z2john path updated: {_7z2johnPath}");
                }

                // Update Perl path
                if (!string.IsNullOrEmpty(settingsWindow.PerlPath))
                {
                    _perlPath = settingsWindow.PerlPath;
                    HashFormatDetector.SetPerlPath(_perlPath);
                    Log($"Perl path updated: {_perlPath}");
                }

                // Update rar2john path
                if (!string.IsNullOrEmpty(settingsWindow.Rar2JohnPath))
                {
                    _rar2johnPath = settingsWindow.Rar2JohnPath;
                    HashFormatDetector.SetRar2JohnPath(_rar2johnPath);
                    Log($"rar2john path updated: {_rar2johnPath}");
                }

                // Update Dictionary path
                if (!string.IsNullOrEmpty(settingsWindow.DictionaryPath))
                {
                    _dictionaryPath = settingsWindow.DictionaryPath;
                    Log($"Dictionary path updated: {_dictionaryPath}");
                }

                SaveSettings();
                Log("Settings saved");
            }
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void BtnMaximize_Click(object sender, RoutedEventArgs e)
        {
            if (WindowState == WindowState.Maximized)
                WindowState = WindowState.Normal;
            else
                WindowState = WindowState.Maximized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        #endregion

        #region Line Graph

        private void UpdateGraph()
        {
            try
            {
                // Add current values to history
                _cpuTempHistory.Add(_cpuTemp > 0 ? _cpuTemp : 40);
                _gpuTempHistory.Add(_gpuTemp > 0 ? _gpuTemp : 40);

                // CPU Usage estimation based on activity
                double cpuUsage = _engine.IsRunning ? 75 + new Random().Next(25) : 10 + new Random().Next(10);
                _cpuUsageHistory.Add(cpuUsage);

                // GPU Usage from hashcat
                double gpuUsage = _hashcatProcess != null && !_hashcatProcess.HasExited ? 90 + new Random().Next(10) : 0;
                _gpuUsageHistory.Add(gpuUsage);

                // Trim histories to max points
                while (_cpuTempHistory.Count > MaxGraphPoints) _cpuTempHistory.RemoveAt(0);
                while (_gpuTempHistory.Count > MaxGraphPoints) _gpuTempHistory.RemoveAt(0);
                while (_cpuUsageHistory.Count > MaxGraphPoints) _cpuUsageHistory.RemoveAt(0);
                while (_gpuUsageHistory.Count > MaxGraphPoints) _gpuUsageHistory.RemoveAt(0);

                // Update labels
                lblCpuTempGraph.Text = $"CPU {_cpuTemp}°";
                lblGpuTempGraph.Text = $"GPU {_gpuTemp}°";
                lblCpuUsage.Text = $" {cpuUsage:F0}%";
                lblGpuUsage.Text = $" {gpuUsage:F0}%";

                // Update large temperature displays (Monitoring Panel)
                lblCpuTempLarge.Text = _cpuTemp > 0 ? $"{_cpuTemp}°C" : "--°C";
                lblGpuTempLarge.Text = _gpuTemp > 0 ? $"{_gpuTemp}°C" : "--°C";
                lblCpuUsageLarge.Text = $"{cpuUsage:F0}%";
                lblGpuUsageLarge.Text = $"{gpuUsage:F0}%";

                // Update temperature graph
                _tempGraphHelper?.AddDataPoint(_cpuTemp, _gpuTemp, cpuUsage, gpuUsage);

                // Draw graph
                DrawLineGraph();
            }
            catch { }
        }

        private void DrawLineGraph()
        {
            if (graphCanvas.ActualWidth <= 0 || graphCanvas.ActualHeight <= 0)
                return;

            graphCanvas.Children.Clear();

            double width = graphCanvas.ActualWidth;
            double height = graphCanvas.ActualHeight;

            // Draw grid lines
            for (int i = 1; i < 4; i++)
            {
                var gridLine = new Line
                {
                    X1 = 0,
                    Y1 = height * i / 4,
                    X2 = width,
                    Y2 = height * i / 4,
                    Stroke = new SolidColorBrush(Color.FromRgb(30, 30, 50)),
                    StrokeThickness = 1
                };
                graphCanvas.Children.Add(gridLine);
            }

            // Draw lines
            DrawLine(_cpuTempHistory, Color.FromRgb(0, 255, 136), width, height, 100);  // CPU Temp (green)
            DrawLine(_gpuTempHistory, Color.FromRgb(255, 107, 53), width, height, 100); // GPU Temp (orange)
            DrawLine(_cpuUsageHistory, Color.FromRgb(0, 245, 255), width, height, 100); // CPU Usage (cyan)
            DrawLine(_gpuUsageHistory, Color.FromRgb(255, 0, 255), width, height, 100); // GPU Usage (pink)
        }

        private void DrawLine(List<double> data, Color color, double width, double height, double maxValue)
        {
            if (data.Count < 2) return;

            var polyline = new Polyline
            {
                Stroke = new SolidColorBrush(color),
                StrokeThickness = 1.5,
                StrokeLineJoin = PenLineJoin.Round
            };

            double stepX = width / (MaxGraphPoints - 1);

            for (int i = 0; i < data.Count; i++)
            {
                double x = i * stepX;
                double y = height - (data[i] / maxValue * height);
                polyline.Points.Add(new System.Windows.Point(x, Math.Max(2, Math.Min(height - 2, y))));
            }

            graphCanvas.Children.Add(polyline);
        }

        #endregion

        #region Speedometer Gauge - Dynamic Car Style

        private double _lastSpeedNeedleAngle = -135; // Starting angle (far left)
        private const double MIN_ANGLE = -135;
        private const double MAX_ANGLE = 135;
        private const double ANGLE_RANGE = 270; // 270 degree arc

        private void InitializeSpeedometer()
        {
            _speedometerMaxScale = 1000; // Start with 1K scale
            _maxSpeedReached = 0;
            DrawSpeedometerBackground();
        }

        private void DrawSpeedometerBackground()
        {
            speedometerCanvas.Children.Clear();

            // Canvas is 120x70, center the gauge properly so needle doesn't overflow
            // Arc spans -135 to +135 degrees, so it's a half-circle pointing down
            double centerX = 60;
            double centerY = 55; // Moved up to prevent bottom overflow
            double radius = 42; // Reduced to fit within bounds

            // Draw outer glow ring
            var glowRing = new Ellipse
            {
                Width = radius * 2 + 8,
                Height = radius * 2 + 8,
                Stroke = new SolidColorBrush(Color.FromArgb(30, 255, 170, 0)),
                StrokeThickness = 4,
                Tag = "background"
            };
            Canvas.SetLeft(glowRing, centerX - radius - 4);
            Canvas.SetTop(glowRing, centerY - radius - 4);
            speedometerCanvas.Children.Add(glowRing);

            // Draw colored zones on the arc (green -> yellow -> red)
            DrawSpeedZoneBackground(centerX, centerY, radius);

            // Draw tick marks with labels
            string[] labels = GetScaleLabels();
            for (int i = 0; i <= 10; i++)
            {
                double angle = MIN_ANGLE + (i * (ANGLE_RANGE / 10));
                double angleRad = angle * Math.PI / 180;
                bool isMajor = i % 2 == 0;
                double innerR = isMajor ? radius - 10 : radius - 6;
                double outerR = radius - 2;

                var tick = new Line
                {
                    X1 = centerX + innerR * Math.Cos(angleRad),
                    Y1 = centerY + innerR * Math.Sin(angleRad),
                    X2 = centerX + outerR * Math.Cos(angleRad),
                    Y2 = centerY + outerR * Math.Sin(angleRad),
                    Stroke = new SolidColorBrush(isMajor ? Color.FromRgb(200, 200, 220) : Color.FromRgb(80, 80, 100)),
                    StrokeThickness = isMajor ? 2 : 1,
                    Tag = "background"
                };
                speedometerCanvas.Children.Add(tick);

                // Add labels for major ticks (reduced label size for compact gauge)
                if (isMajor && i < labels.Length)
                {
                    double labelR = radius - 16;
                    var label = new TextBlock
                    {
                        Text = labels[i / 2],
                        Foreground = new SolidColorBrush(Color.FromRgb(120, 120, 140)),
                        FontSize = 6,
                        FontWeight = FontWeights.Bold,
                        Tag = "background"
                    };
                    double labelX = centerX + labelR * Math.Cos(angleRad) - 6;
                    double labelY = centerY + labelR * Math.Sin(angleRad) - 4;
                    Canvas.SetLeft(label, labelX);
                    Canvas.SetTop(label, labelY);
                    speedometerCanvas.Children.Add(label);
                }
            }

            // Draw redline zone marker at 90% of max
            double redlineAngle = MIN_ANGLE + (0.9 * ANGLE_RANGE);
            double redlineRad = redlineAngle * Math.PI / 180;
            var redline = new Line
            {
                X1 = centerX + (radius - 12) * Math.Cos(redlineRad),
                Y1 = centerY + (radius - 12) * Math.Sin(redlineRad),
                X2 = centerX + radius * Math.Cos(redlineRad),
                Y2 = centerY + radius * Math.Sin(redlineRad),
                Stroke = new SolidColorBrush(Color.FromRgb(255, 50, 50)),
                StrokeThickness = 2,
                Tag = "background"
            };
            speedometerCanvas.Children.Add(redline);
        }

        private string[] GetScaleLabels()
        {
            // Return labels based on current max scale
            if (_speedometerMaxScale >= 10000000) // 10M+
                return new[] { "0", "2M", "4M", "6M", "8M", "10M" };
            else if (_speedometerMaxScale >= 1000000) // 1M+
                return new[] { "0", "200K", "400K", "600K", "800K", "1M" };
            else if (_speedometerMaxScale >= 100000) // 100K+
                return new[] { "0", "20K", "40K", "60K", "80K", "100K" };
            else if (_speedometerMaxScale >= 10000) // 10K+
                return new[] { "0", "2K", "4K", "6K", "8K", "10K" };
            else // 1K
                return new[] { "0", "200", "400", "600", "800", "1K" };
        }

        private void DrawSpeedZoneBackground(double centerX, double centerY, double radius)
        {
            // Draw green zone (0-60%)
            DrawArcZone(centerX, centerY, radius, MIN_ANGLE, MIN_ANGLE + ANGLE_RANGE * 0.6,
                Color.FromArgb(40, 0, 200, 100));

            // Draw yellow zone (60-80%)
            DrawArcZone(centerX, centerY, radius, MIN_ANGLE + ANGLE_RANGE * 0.6, MIN_ANGLE + ANGLE_RANGE * 0.8,
                Color.FromArgb(40, 255, 200, 0));

            // Draw red zone (80-100%)
            DrawArcZone(centerX, centerY, radius, MIN_ANGLE + ANGLE_RANGE * 0.8, MAX_ANGLE,
                Color.FromArgb(60, 255, 50, 50));
        }

        private void DrawArcZone(double centerX, double centerY, double radius, double startAngle, double endAngle, Color color)
        {
            var zonePath = new System.Windows.Shapes.Path
            {
                StrokeThickness = 6,
                Stroke = new SolidColorBrush(color),
                Tag = "background"
            };

            double startRad = startAngle * Math.PI / 180;
            double endRad = endAngle * Math.PI / 180;

            var geometry = new PathGeometry();
            var figure = new PathFigure
            {
                StartPoint = new System.Windows.Point(
                    centerX + radius * Math.Cos(startRad),
                    centerY + radius * Math.Sin(startRad))
            };

            figure.Segments.Add(new ArcSegment
            {
                Point = new System.Windows.Point(
                    centerX + radius * Math.Cos(endRad),
                    centerY + radius * Math.Sin(endRad)),
                Size = new System.Windows.Size(radius, radius),
                SweepDirection = SweepDirection.Clockwise,
                IsLargeArc = (endAngle - startAngle) > 180
            });

            geometry.Figures.Add(figure);
            zonePath.Data = geometry;
            speedometerCanvas.Children.Add(zonePath);
        }

        private void UpdateSpeedometer(long speed)
        {
            // Dynamic scale adjustment - like a real car gauge
            if (speed > _maxSpeedReached)
            {
                _maxSpeedReached = speed;

                // Adjust max scale when speed approaches current max
                double newMaxScale = _speedometerMaxScale;
                if (speed > _speedometerMaxScale * 0.85)
                {
                    // Scale up: 1K -> 10K -> 100K -> 1M -> 10M
                    if (_speedometerMaxScale < 10000) newMaxScale = 10000;
                    else if (_speedometerMaxScale < 100000) newMaxScale = 100000;
                    else if (_speedometerMaxScale < 1000000) newMaxScale = 1000000;
                    else if (_speedometerMaxScale < 10000000) newMaxScale = 10000000;
                    else newMaxScale = 100000000; // 100M max

                    if (newMaxScale != _speedometerMaxScale)
                    {
                        _speedometerMaxScale = newMaxScale;
                        DrawSpeedometerBackground(); // Redraw with new scale
                    }
                }
            }

            // Calculate needle angle - LINEAR scale (like real car gauge)
            double percentage = Math.Min((double)speed / _speedometerMaxScale, 1.0);

            // CRITICAL: Clamp at max angle - needle should NEVER exceed max
            double targetAngle = MIN_ANGLE + (percentage * ANGLE_RANGE);
            targetAngle = Math.Max(MIN_ANGLE, Math.Min(MAX_ANGLE, targetAngle));

            // Smooth animation with different speeds for up/down
            double diff = targetAngle - _lastSpeedNeedleAngle;
            double smoothFactor = diff > 0 ? 0.15 : 0.25; // Slower going up, faster going down
            _lastSpeedNeedleAngle += diff * smoothFactor;

            // Clamp the actual needle position
            _lastSpeedNeedleAngle = Math.Max(MIN_ANGLE, Math.Min(MAX_ANGLE, _lastSpeedNeedleAngle));

            DrawSpeedometerNeedle(_lastSpeedNeedleAngle, percentage);

            // Update speed label with formatting
            string speedText;
            if (speed >= 1000000)
                speedText = $"{speed / 1000000.0:F1}M";
            else if (speed >= 1000)
                speedText = $"{speed / 1000.0:F1}K";
            else
                speedText = speed.ToString("N0");

            lblSpeedGauge.Text = speedText;
        }

        private void DrawSpeedometerNeedle(double angle, double percentage)
        {
            // Remove old dynamic elements
            for (int i = speedometerCanvas.Children.Count - 1; i >= 0; i--)
            {
                var child = speedometerCanvas.Children[i];
                if (child is FrameworkElement fe && fe.Tag?.ToString() != "background")
                {
                    speedometerCanvas.Children.RemoveAt(i);
                }
            }

            // Use same center as background - aligned with DrawSpeedometerBackground
            double centerX = 60;
            double centerY = 55; // Matched to background center
            double needleLength = 32; // Reduced to fit within bounds
            double angleRad = angle * Math.PI / 180;

            // Draw active zone arc first (behind needle)
            DrawActiveZoneArc(centerX, centerY, 42, angle, percentage);

            // Draw needle shadow
            var shadowGeom = CreateNeedleGeometry(centerX + 1, centerY + 1, needleLength - 2, angleRad);
            var shadow = new System.Windows.Shapes.Path
            {
                Data = shadowGeom,
                Fill = new SolidColorBrush(Color.FromArgb(100, 0, 0, 0))
            };
            speedometerCanvas.Children.Add(shadow);

            // Draw main needle with gradient based on speed zone
            Color needleColor1, needleColor2;
            if (percentage < 0.6)
            {
                needleColor1 = Color.FromRgb(0, 255, 136);
                needleColor2 = Color.FromRgb(0, 180, 100);
            }
            else if (percentage < 0.8)
            {
                needleColor1 = Color.FromRgb(255, 200, 0);
                needleColor2 = Color.FromRgb(255, 150, 0);
            }
            else
            {
                needleColor1 = Color.FromRgb(255, 80, 50);
                needleColor2 = Color.FromRgb(200, 30, 30);
            }

            var needleGeom = CreateNeedleGeometry(centerX, centerY, needleLength, angleRad);
            var needle = new System.Windows.Shapes.Path
            {
                Data = needleGeom,
                Fill = new LinearGradientBrush(needleColor1, needleColor2,
                    new System.Windows.Point(0, 0), new System.Windows.Point(1, 1)),
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = needleColor1,
                    BlurRadius = 8,
                    ShadowDepth = 0,
                    Opacity = 0.6
                }
            };
            speedometerCanvas.Children.Add(needle);

            // Draw center cap with metallic look
            var centerOuter = new Ellipse
            {
                Width = 14,
                Height = 14,
                Fill = new RadialGradientBrush(
                    Color.FromRgb(80, 80, 90),
                    Color.FromRgb(40, 40, 50))
            };
            Canvas.SetLeft(centerOuter, centerX - 7);
            Canvas.SetTop(centerOuter, centerY - 7);
            speedometerCanvas.Children.Add(centerOuter);

            var centerInner = new Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = new RadialGradientBrush(needleColor1, needleColor2)
            };
            Canvas.SetLeft(centerInner, centerX - 4);
            Canvas.SetTop(centerInner, centerY - 4);
            speedometerCanvas.Children.Add(centerInner);
        }

        private PathGeometry CreateNeedleGeometry(double centerX, double centerY, double length, double angleRad)
        {
            var geometry = new PathGeometry();
            var figure = new PathFigure { StartPoint = new System.Windows.Point(centerX, centerY) };

            double tipX = centerX + length * Math.Cos(angleRad);
            double tipY = centerY + length * Math.Sin(angleRad);
            double baseAngle1 = angleRad + Math.PI / 2;
            double baseAngle2 = angleRad - Math.PI / 2;
            double baseWidth = 3.5;

            figure.Segments.Add(new LineSegment(new System.Windows.Point(
                centerX + baseWidth * Math.Cos(baseAngle1),
                centerY + baseWidth * Math.Sin(baseAngle1)), true));
            figure.Segments.Add(new LineSegment(new System.Windows.Point(tipX, tipY), true));
            figure.Segments.Add(new LineSegment(new System.Windows.Point(
                centerX + baseWidth * Math.Cos(baseAngle2),
                centerY + baseWidth * Math.Sin(baseAngle2)), true));
            figure.IsClosed = true;

            geometry.Figures.Add(figure);
            return geometry;
        }

        private void DrawActiveZoneArc(double centerX, double centerY, double radius, double needleAngle, double percentage)
        {
            if (needleAngle <= MIN_ANGLE) return;

            // Determine color based on percentage
            Color zoneColor;
            if (percentage < 0.6)
                zoneColor = Color.FromRgb(0, 255, 136);
            else if (percentage < 0.8)
                zoneColor = Color.FromRgb(255, 200, 0);
            else
                zoneColor = Color.FromRgb(255, 80, 50);

            var zonePath = new System.Windows.Shapes.Path
            {
                StrokeThickness = 5,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round,
                Stroke = new SolidColorBrush(zoneColor),
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = zoneColor,
                    BlurRadius = 10,
                    ShadowDepth = 0,
                    Opacity = 0.8
                }
            };

            double startRad = MIN_ANGLE * Math.PI / 180;
            double endRad = needleAngle * Math.PI / 180;

            var geometry = new PathGeometry();
            var figure = new PathFigure
            {
                StartPoint = new System.Windows.Point(
                    centerX + radius * Math.Cos(startRad),
                    centerY + radius * Math.Sin(startRad))
            };

            figure.Segments.Add(new ArcSegment
            {
                Point = new System.Windows.Point(
                    centerX + radius * Math.Cos(endRad),
                    centerY + radius * Math.Sin(endRad)),
                Size = new System.Windows.Size(radius, radius),
                SweepDirection = SweepDirection.Clockwise,
                IsLargeArc = (needleAngle - MIN_ANGLE) > 180
            });

            geometry.Figures.Add(figure);
            zonePath.Data = geometry;
            speedometerCanvas.Children.Add(zonePath);
        }

        #endregion

        #region Firefly Animation

        private void InitializeFireflies()
        {
            // Create initial fireflies (reduced count for performance)
            for (int i = 0; i < 12; i++)
            {
                CreateFirefly();
            }

            // Start animation timer (runs on separate thread-safe dispatcher priority)
            _fireflyTimer = new DispatcherTimer(DispatcherPriority.Background);
            _fireflyTimer.Interval = TimeSpan.FromMilliseconds(50); // ~20 FPS for smoother performance
            _fireflyTimer.Tick += FireflyTimer_Tick;
            _fireflyTimer.Start();
        }

        private void CreateFirefly()
        {
            double width = fireflyCanvas.ActualWidth > 0 ? fireflyCanvas.ActualWidth : 1350;
            double height = fireflyCanvas.ActualHeight > 0 ? fireflyCanvas.ActualHeight : 900;

            var firefly = new Firefly
            {
                X = _fireflyRandom.NextDouble() * width,
                Y = _fireflyRandom.NextDouble() * height,
                VelocityX = (_fireflyRandom.NextDouble() - 0.5) * 2.0,
                VelocityY = (_fireflyRandom.NextDouble() - 0.5) * 2.0,
                Size = 6 + _fireflyRandom.NextDouble() * 10,
                Opacity = 0.6 + _fireflyRandom.NextDouble() * 0.4,
                OpacityDirection = _fireflyRandom.Next(2) == 0 ? 0.015 : -0.015,
                HueOffset = _fireflyRandom.NextDouble() * 360,
                HueSpeed = 0.8 + _fireflyRandom.NextDouble() * 2.5
            };

            // Create visual element with larger size for glow
            var ellipse = new Ellipse
            {
                Width = firefly.Size * 2,
                Height = firefly.Size * 2,
                Fill = GetRainbowBrush(firefly.HueOffset),
                Opacity = firefly.Opacity
            };

            // Add stronger glow effect
            ellipse.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = Colors.Cyan,
                BlurRadius = firefly.Size * 3,
                ShadowDepth = 0,
                Opacity = 0.9
            };

            firefly.Visual = ellipse;
            Canvas.SetLeft(ellipse, firefly.X);
            Canvas.SetTop(ellipse, firefly.Y);

            _fireflies.Add(firefly);
            fireflyCanvas.Children.Add(ellipse);
        }

        private void FireflyTimer_Tick(object sender, EventArgs e)
        {
            double width = fireflyCanvas.ActualWidth;
            double height = fireflyCanvas.ActualHeight;

            if (width <= 0 || height <= 0) return;

            foreach (var firefly in _fireflies)
            {
                // Update position
                firefly.X += firefly.VelocityX;
                firefly.Y += firefly.VelocityY;

                // Bounce off walls with slight randomization
                if (firefly.X < 0 || firefly.X > width)
                {
                    firefly.VelocityX = -firefly.VelocityX + (_fireflyRandom.NextDouble() - 0.5) * 0.3;
                    firefly.X = Math.Max(0, Math.Min(width, firefly.X));
                }
                if (firefly.Y < 0 || firefly.Y > height)
                {
                    firefly.VelocityY = -firefly.VelocityY + (_fireflyRandom.NextDouble() - 0.5) * 0.3;
                    firefly.Y = Math.Max(0, Math.Min(height, firefly.Y));
                }

                // Add slight wandering
                if (_fireflyRandom.Next(100) < 5)
                {
                    firefly.VelocityX += (_fireflyRandom.NextDouble() - 0.5) * 0.5;
                    firefly.VelocityY += (_fireflyRandom.NextDouble() - 0.5) * 0.5;

                    // Limit velocity
                    firefly.VelocityX = Math.Max(-2, Math.Min(2, firefly.VelocityX));
                    firefly.VelocityY = Math.Max(-2, Math.Min(2, firefly.VelocityY));
                }

                // Pulsing opacity
                firefly.Opacity += firefly.OpacityDirection;
                if (firefly.Opacity > 1.0 || firefly.Opacity < 0.2)
                {
                    firefly.OpacityDirection = -firefly.OpacityDirection;
                    firefly.Opacity = Math.Max(0.2, Math.Min(1.0, firefly.Opacity));
                }

                // Update hue for rainbow effect
                firefly.HueOffset += firefly.HueSpeed;
                if (firefly.HueOffset > 360) firefly.HueOffset -= 360;

                // Update visual
                if (firefly.Visual != null)
                {
                    Canvas.SetLeft(firefly.Visual, firefly.X);
                    Canvas.SetTop(firefly.Visual, firefly.Y);
                    firefly.Visual.Opacity = firefly.Opacity;
                    firefly.Visual.Fill = GetRainbowBrush(firefly.HueOffset);
                }
            }
        }

        /// <summary>
        /// Calculate total possible passwords based on attack mode and settings
        /// </summary>
        private long CalculateTotalPossiblePasswords(AttackMode mode, int minLen, int maxLen)
        {
            long total = 0;
            int charsetSize = mode switch
            {
                AttackMode.BruteForceNumbers => 10,  // 0-9
                AttackMode.BruteForceLowercase => 26,  // a-z
                AttackMode.BruteForceAlphanumeric => 62,  // a-z A-Z 0-9
                AttackMode.BruteForceAll => 77,  // a-z A-Z 0-9 + special
                AttackMode.Smart => 10,  // Start with numbers for Smart mode
                _ => 62  // Default alphanumeric
            };

            // Calculate sum of combinations for each length
            for (int len = minLen; len <= maxLen; len++)
            {
                // Use checked to avoid overflow, cap at long.MaxValue
                try
                {
                    checked
                    {
                        total += (long)Math.Pow(charsetSize, len);
                    }
                }
                catch (OverflowException)
                {
                    return long.MaxValue / 2;  // Cap at reasonable value
                }
            }

            return total;
        }

        private Brush GetRainbowBrush(double hue)
        {
            // Convert HSL to RGB with high saturation and brightness
            double h = hue / 60.0;
            int i = (int)Math.Floor(h) % 6;
            double f = h - Math.Floor(h);

            // High saturation vibrant colors
            double v = 1.0;
            double p = 0.0;
            double q = 1.0 - f;
            double t = f;

            double r, g, b;
            switch (i)
            {
                case 0: r = v; g = t; b = p; break;  // Red to Yellow
                case 1: r = q; g = v; b = p; break;  // Yellow to Green
                case 2: r = p; g = v; b = t; break;  // Green to Cyan
                case 3: r = p; g = q; b = v; break;  // Cyan to Blue
                case 4: r = t; g = p; b = v; break;  // Blue to Magenta
                default: r = v; g = p; b = q; break; // Magenta to Red
            }

            // Create radial gradient for glowing effect
            var brush = new RadialGradientBrush();
            brush.GradientOrigin = new Point(0.5, 0.5);
            brush.Center = new Point(0.5, 0.5);
            brush.RadiusX = 0.5;
            brush.RadiusY = 0.5;

            var coreColor = Color.FromRgb((byte)(r * 255), (byte)(g * 255), (byte)(b * 255));
            brush.GradientStops.Add(new GradientStop(Colors.White, 0.0));
            brush.GradientStops.Add(new GradientStop(coreColor, 0.3));
            brush.GradientStops.Add(new GradientStop(Color.FromArgb(128, coreColor.R, coreColor.G, coreColor.B), 0.7));
            brush.GradientStops.Add(new GradientStop(Colors.Transparent, 1.0));

            return brush;
        }

        #endregion

        #region Charset and Work Manager

        /// <summary>
        /// อัปเดตข้อมูล charset และคำนวณ total passwords
        /// </summary>
        private void UpdateCharsetInfo()
        {
            if (_workManager == null) return;

            // อัปเดต charset options
            _workManager.UseNumbers = chkNumbers.IsChecked == true;
            _workManager.UseLowercase = chkLowercase.IsChecked == true;
            _workManager.UseUppercase = chkUppercase.IsChecked == true;
            _workManager.UseSpecial = chkSpecial.IsChecked == true;

            // อัปเดต password length
            if (int.TryParse(txtMinLen.Text, out int minLen) && int.TryParse(txtMaxLen.Text, out int maxLen))
            {
                _workManager.MinLength = Math.Max(1, minLen);
                _workManager.MaxLength = Math.Max(minLen, maxLen);
            }

            // คำนวณ charset size
            _workManager.UpdateCharset();
            int charsetSize = _workManager.ActiveCharset.Length;
            lblCharsetInfo.Text = $"{charsetSize} chars";

            // คำนวณ total passwords
            var total = _workManager.CalculateTotalPasswords();
            lblTotalPasswords.Text = WorkChunkManager.FormatBigNumber(total);
            lblTotalPasswordsDetail.Text = $"{total:N0} combinations";
        }

        /// <summary>
        /// Event handler เมื่อ charset checkbox เปลี่ยน
        /// </summary>
        private void Charset_Changed(object sender, RoutedEventArgs e)
        {
            UpdateCharsetInfo();
        }

        /// <summary>
        /// Event handler เมื่อความยาว password เปลี่ยน
        /// </summary>
        private void PasswordLength_Changed(object sender, TextChangedEventArgs e)
        {
            UpdateCharsetInfo();
        }

        /// <summary>
        /// Event handler เมื่อ focus ออกจาก textbox ความยาว - ตรวจสอบ min/max
        /// </summary>
        private void PasswordLength_LostFocus(object sender, RoutedEventArgs e)
        {
            ValidatePasswordLength();
            UpdateCharsetInfo();
        }

        /// <summary>
        /// ตรวจสอบและแก้ไข min/max ให้ถูกต้อง
        /// </summary>
        private void ValidatePasswordLength()
        {
            if (!int.TryParse(txtMinLen.Text, out int minLen))
            {
                minLen = 1;
                txtMinLen.Text = "1";
            }

            if (!int.TryParse(txtMaxLen.Text, out int maxLen))
            {
                maxLen = 8;
                txtMaxLen.Text = "8";
            }

            // ต้องมีค่าอย่างน้อย 1
            if (minLen < 1)
            {
                minLen = 1;
                txtMinLen.Text = "1";
            }

            if (maxLen < 1)
            {
                maxLen = 1;
                txtMaxLen.Text = "1";
            }

            // min ต้องไม่เกิน max
            if (minLen > maxLen)
            {
                // ถ้า user แก้ min ให้เกิน max → ปรับ max ขึ้น
                // ถ้า user แก้ max ให้ต่ำกว่า min → ปรับ min ลง
                var focusedElement = Keyboard.FocusedElement;
                if (focusedElement == txtMinLen)
                {
                    maxLen = minLen;
                    txtMaxLen.Text = maxLen.ToString();
                }
                else
                {
                    minLen = maxLen;
                    txtMinLen.Text = minLen.ToString();
                }
            }

            // จำกัด max ไม่เกิน 10 (ป้องกัน overflow และใช้เวลานานมาก)
            if (maxLen > 10)
            {
                maxLen = 10;
                txtMaxLen.Text = "10";
            }
        }

        /// <summary>
        /// อัปเดต CPU progress section with beautiful progress bar
        /// </summary>
        private void UpdateCpuProgress(string pattern, long checkedCount, double progressPercent, long current, long total, string action, string eta = "--")
        {
            Dispatcher.InvokeAsync(() =>
            {
                lblCpuPattern.Text = pattern;
                lblCpuChecked.Text = FormatNumber(checkedCount);
                lblCpuChunkProgress.Text = $"{progressPercent:F1}%";
                progressBarCpuChunk.Value = progressPercent;
                lblCpuChunkInfo.Text = $"{FormatNumber(current)}/{FormatNumber(total)}";
                lblCpuCurrentAction.Text = action;
                lblCpuEta.Text = eta;

                // Clamp progress
                double safeProgress = Math.Min(100, Math.Max(0, progressPercent));

                // Update OVERALL progress bar (Green) - แสดง progress รวม
                lblCpuProgressPercent.Text = $"{safeProgress:F1}%";
                lblCpuPhaseInfo.Text = total > 0 ? $"{FormatNumber(current)}/{FormatNumber(total)}" : "";
                double overallContainerWidth = cpuProgressFill.Parent is FrameworkElement overallParent ? overallParent.ActualWidth : 300;
                cpuProgressFill.Width = Math.Max(0, overallContainerWidth * (safeProgress / 100.0));

                // Update FILE progress bar (Cyan) - แสดง progress เหมือนกัน (CPU ไม่มี multi-file)
                lblCpuWordlistPercent.Text = $"{safeProgress:F0}%";
                lblCpuWordlistDetail.Text = total > 0 ? $"{FormatNumber(current)}/{FormatNumber(total)}" : "";
                double wordlistContainerWidth = cpuWordlistProgressFill.Parent is FrameworkElement wordlistParent ? wordlistParent.ActualWidth : 300;
                cpuWordlistProgressFill.Width = Math.Max(0, wordlistContainerWidth * (safeProgress / 100.0));
            });
        }

        /// <summary>
        /// อัปเดต GPU progress section with beautiful progress bar
        /// </summary>
        private void UpdateGpuProgress(string pattern, long checkedCount, double chunkProgress, long chunkCurrent, long chunkTotal, string action, string eta = "--")
        {
            Dispatcher.InvokeAsync(() =>
            {
                lblGpuPattern.Text = pattern;
                lblGpuChecked.Text = FormatNumber(checkedCount);
                lblGpuChunkProgress.Text = $"{chunkProgress:F1}%";
                progressBarGpuChunk.Value = chunkProgress;
                lblGpuChunkInfo.Text = $"{FormatNumber(chunkCurrent)}/{FormatNumber(chunkTotal)}";
                lblGpuCurrentAction.Text = action;
                lblGpuEta.Text = eta;

                // Calculate OVERALL progress based on phases:
                // overallProgress = ((completedPhases + currentPhaseProgress/100) / totalPhases) * 100
                // This ensures smooth progress across all phases
                double calculatedProgress = 0;
                if (_totalGpuPhases > 0)
                {
                    // completedPhases = _currentGpuPhase - 1 (phases before current one)
                    // currentPhaseProgress = chunkProgress (0-100%)
                    int completedPhases = Math.Max(0, _currentGpuPhase - 1);
                    double currentPhaseContribution = chunkProgress / 100.0;  // Convert 0-100 to 0-1
                    calculatedProgress = ((completedPhases + currentPhaseContribution) / _totalGpuPhases) * 100.0;
                    calculatedProgress = Math.Min(100, Math.Max(0, calculatedProgress));
                }
                else
                {
                    calculatedProgress = chunkProgress; // Fallback to phase progress
                }

                // TOTAL progress must NEVER decrease - only increase or stay the same
                // This prevents the progress bar from jumping back when switching phases
                if (calculatedProgress > _gpuOverallProgress)
                {
                    _gpuOverallProgress = calculatedProgress;
                }

                // Update OVERALL progress bar (Orange) - use stored value that never decreases
                lblGpuProgressPercent.Text = $"{_gpuOverallProgress:F1}%";
                lblGpuPhaseInfo.Text = _currentGpuPhase > 0 ? $"Phase {_currentGpuPhase}/{_totalGpuPhases}" : "";
                double overallContainerWidth = gpuProgressFill.Parent is FrameworkElement overallParent ? overallParent.ActualWidth : 300;
                gpuProgressFill.Width = Math.Max(0, overallContainerWidth * (_gpuOverallProgress / 100.0));

                // Update PHASE progress bar (Purple) - shows current phase progress
                lblGpuPhasePercent.Text = $"{chunkProgress:F0}%";
                lblGpuPhaseDetail.Text = _currentGpuPhase > 0 ? $"{_currentGpuPhase}/{_totalGpuPhases}" : "";
                double phaseContainerWidth = gpuPhaseProgressFill.Parent is FrameworkElement phaseParent ? phaseParent.ActualWidth : 300;
                gpuPhaseProgressFill.Width = Math.Max(0, phaseContainerWidth * (chunkProgress / 100.0));
            });
        }

        // GPU phase tracking
        private int _currentGpuPhase = 0;
        private int _totalGpuPhases = 0;

        // Attack strategy
        private AttackStrategy _selectedStrategy = AttackStrategy.LengthFirst;
        private List<StrategyItem> _strategyItems;

        /// <summary>
        /// Initialize the strategy ComboBox with items
        /// </summary>
        private void InitializeStrategyComboBox()
        {
            _strategyItems = new List<StrategyItem>
            {
                new StrategyItem
                {
                    Icon = "🚀",
                    Name = "Length-First",
                    Description = "Test short passwords first (recommended)",
                    Strategy = AttackStrategy.LengthFirst
                },
                new StrategyItem
                {
                    Icon = "🎯",
                    Name = "Pattern-First",
                    Description = "Test all lengths per pattern type",
                    Strategy = AttackStrategy.PatternFirst
                },
                new StrategyItem
                {
                    Icon = "🔀",
                    Name = "Smart Mix",
                    Description = "Interleave patterns intelligently",
                    Strategy = AttackStrategy.SmartMix
                },
                new StrategyItem
                {
                    Icon = "⭐",
                    Name = "Common-First",
                    Description = "Test common passwords first",
                    Strategy = AttackStrategy.CommonFirst
                }
            };

            cboStrategy.ItemsSource = _strategyItems;
            cboStrategy.SelectedIndex = 0;
            cboStrategy.SelectionChanged += CboStrategy_SelectionChanged;
        }

        private void CboStrategy_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (cboStrategy.SelectedItem is StrategyItem item)
            {
                _selectedStrategy = item.Strategy;
                Log($"Strategy changed to: {item.Icon} {item.Name}");
                SystemLog($"Attack strategy: {item.Name} - {item.Description}");
            }
        }

        /// <summary>
        /// Build attack phases based on selected strategy
        /// Returns list of (name, charset, mask, minLen, maxLen)
        /// </summary>
        private List<(string name, string charset, string mask, int minLen, int maxLen)> BuildAttackPhases(
            AttackStrategy strategy, bool hasNumbers, bool hasLower, bool hasUpper, bool hasSpecial,
            int globalMinLen, int globalMaxLen, string fullCharset)
        {
            var phases = new List<(string name, string charset, string mask, int minLen, int maxLen)>();

            switch (strategy)
            {
                case AttackStrategy.LengthFirst:
                    phases = BuildLengthFirstPhases(hasNumbers, hasLower, hasUpper, hasSpecial, globalMinLen, globalMaxLen, fullCharset);
                    break;

                case AttackStrategy.PatternFirst:
                    phases = BuildPatternFirstPhases(hasNumbers, hasLower, hasUpper, hasSpecial, globalMinLen, globalMaxLen, fullCharset);
                    break;

                case AttackStrategy.SmartMix:
                    phases = BuildSmartMixPhases(hasNumbers, hasLower, hasUpper, hasSpecial, globalMinLen, globalMaxLen, fullCharset);
                    break;

                case AttackStrategy.CommonFirst:
                    phases = BuildCommonFirstPhases(hasNumbers, hasLower, hasUpper, hasSpecial, globalMinLen, globalMaxLen, fullCharset);
                    break;
            }

            return phases;
        }

        /// <summary>
        /// 🚀 Length-First: ใช้ --increment เพื่อทดสอบทุก length ใน process เดียว
        /// เรียงลำดับ: ง่ายก่อน (Numbers) → ยากขึ้น (Full charset)
        /// ลดจำนวน phases จาก 56 → ~7 phases เพื่อลด hashcat startup overhead
        /// </summary>
        private List<(string name, string charset, string mask, int minLen, int maxLen)> BuildLengthFirstPhases(
            bool hasNumbers, bool hasLower, bool hasUpper, bool hasSpecial,
            int minLen, int maxLen, string fullCharset)
        {
            var phases = new List<(string name, string charset, string mask, int minLen, int maxLen)>();

            // Build charset dynamically based on selected options
            // Hashcat charset: ?d=digits, ?l=lowercase, ?u=uppercase, ?s=special
            var charsetParts = new List<string>();
            var nameParts = new List<string>();

            if (hasNumbers)
            {
                charsetParts.Add("?d");
                nameParts.Add("0-9");
            }
            if (hasLower)
            {
                charsetParts.Add("?l");
                nameParts.Add("a-z");
            }
            if (hasUpper)
            {
                charsetParts.Add("?u");
                nameParts.Add("A-Z");
            }
            if (hasSpecial)
            {
                charsetParts.Add("?s");
                nameParts.Add("Special");
            }

            // If nothing selected, use all
            if (charsetParts.Count == 0)
            {
                charsetParts.Add("?a");
                nameParts.Add("All");
            }

            string charset = string.Join("", charsetParts);
            string charsetName = string.Join("+", nameParts);

            // Length-First: Create one phase per length (iterate by length, not by pattern)
            // Each phase tests ALL passwords of a specific length using the selected charset
            for (int len = minLen; len <= maxLen; len++)
            {
                string mask;
                if (charsetParts.Count == 1)
                {
                    // Single charset like ?d, ?l, ?u, ?s, ?a - repeat directly
                    // e.g., ?d?d?d for 3-digit numbers
                    mask = string.Concat(Enumerable.Repeat(charset, len));
                }
                else
                {
                    // Multiple charsets combined - will use -1 custom charset, so mask uses ?1
                    // e.g., ?1?1?1 for 3-char with custom charset
                    mask = string.Concat(Enumerable.Repeat("?1", len));
                }

                phases.Add(($"{charsetName} (len={len})", charset, mask, len, len));
            }

            return phases;
        }

        /// <summary>
        /// 🎯 Pattern-First: Test all lengths for each pattern before moving to next pattern
        /// Order: Numbers 1-8, Lowercase 1-8, Uppercase 1-8, Mixed 1-8...
        /// </summary>
        private List<(string name, string charset, string mask, int minLen, int maxLen)> BuildPatternFirstPhases(
            bool hasNumbers, bool hasLower, bool hasUpper, bool hasSpecial,
            int minLen, int maxLen, string fullCharset)
        {
            var phases = new List<(string name, string charset, string mask, int minLen, int maxLen)>();
            string maxMask = new string('?', maxLen);

            // Phase group 1: Numbers only (all lengths)
            if (hasNumbers)
            {
                phases.Add(("Numbers (0-9)", "?d", maxMask.Replace("?", "?d"), minLen, maxLen));
            }

            // Phase group 2: Lowercase only
            if (hasLower)
            {
                phases.Add(("Lowercase (a-z)", "?l", maxMask.Replace("?", "?l"), minLen, maxLen));
            }

            // Phase group 3: Uppercase only
            if (hasUpper)
            {
                phases.Add(("Uppercase (A-Z)", "?u", maxMask.Replace("?", "?u"), minLen, maxLen));
            }

            // Phase group 4: Numbers + Lowercase
            if (hasNumbers && hasLower)
            {
                phases.Add(("Num+Lowercase", "?d?l", maxMask.Replace("?", "?1"), minLen, maxLen));
            }

            // Phase group 5: Numbers + Uppercase
            if (hasNumbers && hasUpper)
            {
                phases.Add(("Num+Uppercase", "?d?u", maxMask.Replace("?", "?1"), minLen, maxLen));
            }

            // Phase group 6: All letters
            if (hasLower && hasUpper)
            {
                phases.Add(("All Letters", "?l?u", maxMask.Replace("?", "?1"), minLen, maxLen));
            }

            // Phase group 7: Alphanumeric
            if (hasNumbers && hasLower && hasUpper)
            {
                phases.Add(("Alphanumeric", "?d?l?u", maxMask.Replace("?", "?1"), minLen, maxLen));
            }

            // Phase group 8: With special
            if (hasSpecial)
            {
                phases.Add(($"Full charset", fullCharset, maxMask.Replace("?", "?1"), minLen, maxLen));
            }

            return phases;
        }

        /// <summary>
        /// 🔀 Smart Mix: Interleave patterns and lengths for balanced coverage
        /// Prioritizes: short+simple, then gradually increases complexity
        /// </summary>
        private List<(string name, string charset, string mask, int minLen, int maxLen)> BuildSmartMixPhases(
            bool hasNumbers, bool hasLower, bool hasUpper, bool hasSpecial,
            int minLen, int maxLen, string fullCharset)
        {
            var phases = new List<(string name, string charset, string mask, int minLen, int maxLen)>();

            // Round 1: Very short passwords (1-3 chars) - all patterns
            if (minLen <= 3)
            {
                int roundMax = Math.Min(3, maxLen);
                string mask = new string('?', roundMax);

                if (hasNumbers)
                    phases.Add(($"Quick: Numbers 1-{roundMax}", "?d", mask.Replace("?", "?d"), minLen, roundMax));
                if (hasLower)
                    phases.Add(($"Quick: Lowercase 1-{roundMax}", "?l", mask.Replace("?", "?l"), minLen, roundMax));
                if (hasUpper)
                    phases.Add(($"Quick: Uppercase 1-{roundMax}", "?u", mask.Replace("?", "?u"), minLen, roundMax));
                if (hasNumbers && hasLower)
                    phases.Add(($"Quick: Num+Lower 1-{roundMax}", "?d?l", mask.Replace("?", "?1"), minLen, roundMax));
            }

            // Round 2: Medium passwords (4-6 chars) - common patterns
            if (maxLen >= 4)
            {
                int roundMin = Math.Max(4, minLen);
                int roundMax = Math.Min(6, maxLen);
                if (roundMin <= roundMax)
                {
                    string mask = new string('?', roundMax);

                    if (hasNumbers)
                        phases.Add(($"PIN codes {roundMin}-{roundMax}", "?d", mask.Replace("?", "?d"), roundMin, roundMax));
                    if (hasNumbers && hasLower)
                        phases.Add(($"Common {roundMin}-{roundMax}", "?d?l", mask.Replace("?", "?1"), roundMin, roundMax));
                    if (hasLower)
                        phases.Add(($"Words {roundMin}-{roundMax}", "?l", mask.Replace("?", "?l"), roundMin, roundMax));
                    if (hasUpper)
                        phases.Add(($"Uppercase {roundMin}-{roundMax}", "?u", mask.Replace("?", "?u"), roundMin, roundMax));
                }
            }

            // Round 3: Longer passwords (7-8 chars)
            if (maxLen >= 7)
            {
                int roundMin = Math.Max(7, minLen);
                int roundMax = maxLen;
                if (roundMin <= roundMax)
                {
                    string mask = new string('?', roundMax);

                    if (hasNumbers)
                        phases.Add(($"Long Numbers {roundMin}-{roundMax}", "?d", mask.Replace("?", "?d"), roundMin, roundMax));
                    if (hasLower)
                        phases.Add(($"Long Lowercase {roundMin}-{roundMax}", "?l", mask.Replace("?", "?l"), roundMin, roundMax));
                    if (hasUpper)
                        phases.Add(($"Long Uppercase {roundMin}-{roundMax}", "?u", mask.Replace("?", "?u"), roundMin, roundMax));
                    if (hasNumbers && hasLower)
                        phases.Add(($"Long Mixed {roundMin}-{roundMax}", "?d?l", mask.Replace("?", "?1"), roundMin, roundMax));
                    if (hasNumbers && hasLower && hasUpper)
                        phases.Add(($"Long Alphanum {roundMin}-{roundMax}", "?d?l?u", mask.Replace("?", "?1"), roundMin, roundMax));
                }
            }

            // Round 4: Full charset sweep
            if (hasSpecial || (hasNumbers && hasLower && hasUpper))
            {
                string mask = new string('?', maxLen);
                string charset = hasSpecial ? fullCharset : "?d?l?u";
                phases.Add(($"Full sweep {minLen}-{maxLen}", charset, mask.Replace("?", "?1"), minLen, maxLen));
            }

            return phases;
        }

        /// <summary>
        /// ⭐ Common-First: Test common password patterns first
        /// Order: Common passwords, PIN codes, then brute force
        /// </summary>
        private List<(string name, string charset, string mask, int minLen, int maxLen)> BuildCommonFirstPhases(
            bool hasNumbers, bool hasLower, bool hasUpper, bool hasSpecial,
            int minLen, int maxLen, string fullCharset)
        {
            var phases = new List<(string name, string charset, string mask, int minLen, int maxLen)>();

            // Phase 1: 4-6 digit PINs (most common)
            if (hasNumbers && minLen <= 6)
            {
                int pinMin = Math.Max(4, minLen);
                int pinMax = Math.Min(6, maxLen);
                if (pinMin <= pinMax)
                {
                    string mask = new string('?', pinMax);
                    phases.Add(($"PIN codes {pinMin}-{pinMax}", "?d", mask.Replace("?", "?d"), pinMin, pinMax));
                }
            }

            // Phase 2: Short numeric (1-3 digits)
            if (hasNumbers && minLen <= 3)
            {
                string mask = new string('?', 3);
                phases.Add(($"Short numbers 1-3", "?d", mask.Replace("?", "?d"), minLen, Math.Min(3, maxLen)));
            }

            // Phase 3: Common word lengths (6-8 chars lowercase/uppercase)
            if (hasLower && maxLen >= 6)
            {
                int wordMin = Math.Max(6, minLen);
                int wordMax = Math.Min(8, maxLen);
                if (wordMin <= wordMax)
                {
                    string mask = new string('?', wordMax);
                    phases.Add(($"Words {wordMin}-{wordMax}", "?l", mask.Replace("?", "?l"), wordMin, wordMax));
                }
            }
            if (hasUpper && maxLen >= 6)
            {
                int wordMin = Math.Max(6, minLen);
                int wordMax = Math.Min(8, maxLen);
                if (wordMin <= wordMax)
                {
                    string mask = new string('?', wordMax);
                    phases.Add(($"Uppercase {wordMin}-{wordMax}", "?u", mask.Replace("?", "?u"), wordMin, wordMax));
                }
            }

            // Phase 4: Mixed alphanumeric (common like "pass123")
            if (hasNumbers && hasLower)
            {
                int mixMin = Math.Max(4, minLen);
                int mixMax = Math.Min(8, maxLen);
                if (mixMin <= mixMax)
                {
                    string mask = new string('?', mixMax);
                    phases.Add(($"Mixed {mixMin}-{mixMax}", "?d?l", mask.Replace("?", "?1"), mixMin, mixMax));
                }
            }

            // Phase 5: All remaining patterns - full brute force
            string finalMask = new string('?', maxLen);
            if (hasSpecial)
            {
                phases.Add(($"Full brute force", fullCharset, finalMask.Replace("?", "?1"), minLen, maxLen));
            }
            else if (hasNumbers && hasLower && hasUpper)
            {
                phases.Add(($"Alphanumeric full", "?d?l?u", finalMask.Replace("?", "?1"), minLen, maxLen));
            }
            else if (hasNumbers)
            {
                // If only numbers selected, test longer numbers
                phases.Add(($"All numbers {minLen}-{maxLen}", "?d", finalMask.Replace("?", "?d"), minLen, maxLen));
            }
            else if (hasLower)
            {
                phases.Add(($"All lowercase {minLen}-{maxLen}", "?l", finalMask.Replace("?", "?l"), minLen, maxLen));
            }
            else if (hasUpper)
            {
                phases.Add(($"All uppercase {minLen}-{maxLen}", "?u", finalMask.Replace("?", "?u"), minLen, maxLen));
            }

            return phases;
        }

        /// <summary>
        /// คำนวณ ETA จากความเร็วและจำนวนที่เหลือ
        /// </summary>
        private string CalculateEta(long remaining, long speed)
        {
            if (speed <= 0 || remaining <= 0) return "--";

            long secondsRemaining = remaining / speed;

            if (secondsRemaining < 60)
                return $"{secondsRemaining}s";
            if (secondsRemaining < 3600)
                return $"{secondsRemaining / 60}m {secondsRemaining % 60}s";
            if (secondsRemaining < 86400)
                return $"{secondsRemaining / 3600}h {(secondsRemaining % 3600) / 60}m";
            if (secondsRemaining < 86400 * 365)
                return $"{secondsRemaining / 86400}d {(secondsRemaining % 86400) / 3600}h";

            // มากกว่า 1 ปี
            long years = secondsRemaining / (86400 * 365);
            if (years > 1000)
                return ">1000y";
            return $"{years}y";
        }

        /// <summary>
        /// รีเซ็ต progress sections
        /// </summary>
        private void ResetProgressSections()
        {
            Dispatcher.InvokeAsync(() =>
            {
                // CPU
                lblCpuPattern.Text = "Idle";
                lblCpuChecked.Text = "0";
                lblCpuChunkProgress.Text = "0%";
                progressBarCpuChunk.Value = 0;
                lblCpuChunkInfo.Text = "0/0";
                lblCpuCurrentAction.Text = "Idle";
                lblCpuEta.Text = "--";

                // CPU beautiful progress bars
                lblCpuProgressPercent.Text = "0%";
                lblCpuPhaseInfo.Text = "";
                cpuProgressFill.Width = 0;
                lblCpuWordlistPercent.Text = "0%";
                lblCpuWordlistDetail.Text = "";
                cpuWordlistProgressFill.Width = 0;

                // GPU
                lblGpuPattern.Text = "Idle";
                lblGpuChecked.Text = "0";
                lblGpuChunkProgress.Text = "0%";
                progressBarGpuChunk.Value = 0;
                lblGpuChunkInfo.Text = "0/0";
                lblGpuCurrentAction.Text = "Idle";
                lblGpuEta.Text = "--";

                // GPU beautiful progress bars
                lblGpuProgressPercent.Text = "0%";
                lblGpuPhaseInfo.Text = "";
                gpuProgressFill.Width = 0;
                lblGpuPhasePercent.Text = "0%";
                lblGpuPhaseDetail.Text = "";
                gpuPhaseProgressFill.Width = 0;

                // Reset phase tracking
                _currentGpuPhase = 0;
                _totalGpuPhases = 0;
            });
        }

        /// <summary>
        /// Format ตัวเลขให้อ่านง่าย
        /// </summary>
        private string FormatNumber(long number)
        {
            if (number < 1000) return number.ToString();
            if (number < 1_000_000) return $"{number / 1000.0:F1}K";
            if (number < 1_000_000_000) return $"{number / 1_000_000.0:F2}M";
            return $"{number / 1_000_000_000.0:F2}B";
        }

        /// <summary>
        /// แสดงข้อความเจอ password ในฝั่งที่เจอ
        /// </summary>
        private void ShowPasswordFoundInLog(string password, string foundBy)
        {
            string message = $"\n🎉🎉🎉 PASSWORD FOUND! 🎉🎉🎉\n" +
                           $"Password: {password}\n" +
                           $"Found by: {foundBy}\n";

            if (foundBy == "CPU")
            {
                Log(message);
                UpdateCpuProgress("✓ FOUND",
                                 _workManager?.CpuStats.TotalTested ?? 0,
                                 100, 1, 1, "PASSWORD FOUND!");
            }
            else
            {
                GpuLog(message);
                UpdateGpuProgress("✓ FOUND",
                                 _workManager?.GpuStats.TotalTested ?? 0,
                                 100, 1, 1, "PASSWORD FOUND!");
            }
        }

        #endregion

        #region Checkpoint & Resume

        private void CheckpointTimer_Tick(object sender, EventArgs e)
        {
            // Auto-save checkpoint every 10 seconds
            SaveCheckpoint();
        }

        private void SaveCheckpoint()
        {
            try
            {
                if (string.IsNullOrEmpty(txtFilePath.Text) || !File.Exists(txtFilePath.Text))
                    return;

                // Don't save if password already found
                if (_passwordFound)
                    return;

                // Get current attack mode
                string attackMode = GetCurrentAttackMode();
                if (string.IsNullOrEmpty(attackMode))
                    return;

                var checkpoint = new CheckpointData
                {
                    ArchivePath = txtFilePath.Text,
                    LastSaved = DateTime.Now,
                    AttackMode = attackMode,

                    // CPU state
                    CpuTestedCount = _engine?.TotalAttempts ?? 0,
                    CpuNextChunkStart = _workManager?.CpuStats?.ChunkEndIndex ?? 0,

                    // GPU state
                    GpuTestedCount = _gpuTestedCount,
                    GpuProgress = (int)_gpuProgress,
                    GpuNextChunkStart = _workManager?.GpuStats?.ChunkEndIndex ?? 0,

                    // v1.6: GPU phase tracking
                    CurrentGpuPhase = _currentGpuPhase,
                    TotalGpuPhases = _totalGpuPhases,
                    GpuTotalTestedCount = _gpuTotalTestedCount,
                    GpuOverallProgress = _gpuOverallProgress,

                    // Work configuration
                    MinLength = _engine?.MinLength ?? _workManager?.MinLength ?? 1,
                    MaxLength = _engine?.MaxLength ?? _workManager?.MaxLength ?? 8,
                    Charset = _workManager?.ActiveCharset ?? "",
                    ThreadCount = _engine?.ThreadCount ?? Environment.ProcessorCount,

                    // Overall stats
                    TotalPasswords = _totalPossiblePasswords,
                    ElapsedSeconds = _stopwatch?.Elapsed.TotalSeconds ?? 0,

                    // Custom pattern
                    CustomPattern = txtPattern?.Text ?? "",

                    // v1.7: Dictionary resume support
                    DictionaryLinePosition = _engine?.DictionaryLinePosition ?? 0,
                    DictionaryPath = _dictionaryPath ?? "",

                    // v1.5: Dynamic worker switching
                    WorkerConfiguration = new WorkerConfig
                    {
                        UseCpu = chkCpu?.IsChecked == true,
                        UseGpu = chkGpu?.IsChecked == true
                    },
                    CpuWorkerProgress = new WorkerProgress
                    {
                        StartPosition = _cpuStartPosition,
                        CurrentPosition = _cpuCurrentPosition,
                        EndPosition = _cpuEndPosition,
                        Speed = _cpuSpeed
                    },
                    GpuWorkerProgress = new WorkerProgress
                    {
                        StartPosition = _gpuStartPosition,
                        CurrentPosition = _gpuCurrentPosition,
                        EndPosition = _gpuEndPosition,
                        Speed = _gpuSpeed
                    },
                    TotalPasswordSpace = _totalPasswordSpace
                };

                CheckpointManager.SaveCheckpoint(checkpoint);
            }
            catch (Exception ex)
            {
                // Silent fail - checkpoint is optional
                System.Diagnostics.Debug.WriteLine($"Checkpoint save error: {ex.Message}");
            }
        }

        private string GetCurrentAttackMode()
        {
            // Build attack mode name from selected checkboxes
            var parts = new List<string>();
            if (chkNumbers?.IsChecked == true) parts.Add("Numbers");
            if (chkLowercase?.IsChecked == true) parts.Add("Lowercase");
            if (chkUppercase?.IsChecked == true) parts.Add("Uppercase");
            if (chkSpecial?.IsChecked == true) parts.Add("Special");

            if (parts.Count == 0) return "None";
            if (parts.Count == 4) return "All Characters";
            return string.Join("+", parts);
        }

        private void BtnResume_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Get list of available checkpoints
                var checkpoints = CheckpointManager.GetAllCheckpoints();

                if (checkpoints.Count == 0)
                {
                    MessageBox.Show("No saved checkpoints found.", "Resume", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // Show checkpoint selection dialog
                var dialog = new CheckpointSelectionDialog(checkpoints);
                if (dialog.ShowDialog() == true && dialog.SelectedCheckpoint != null)
                {
                    var info = dialog.SelectedCheckpoint;

                    // Load full checkpoint data
                    var checkpoint = CheckpointManager.LoadCheckpoint(info.ArchivePath);
                    if (checkpoint == null)
                    {
                        MessageBox.Show("Failed to load checkpoint.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    // Load the archive file
                    txtFilePath.Text = checkpoint.ArchivePath;
                    if (!_engine.LoadZipFile(checkpoint.ArchivePath))
                    {
                        MessageBox.Show("Failed to load archive file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    UpdateFileInfoDisplay();

                    // Restore configuration
                    _engine.MinLength = checkpoint.MinLength;
                    _engine.MaxLength = checkpoint.MaxLength;
                    _engine.ThreadCount = checkpoint.ThreadCount;
                    txtThreads.Text = checkpoint.ThreadCount.ToString();

                    if (!string.IsNullOrEmpty(checkpoint.CustomPattern))
                        txtPattern.Text = checkpoint.CustomPattern;

                    // Set attack mode
                    SetAttackMode(checkpoint.AttackMode);

                    // Restore work manager state
                    _workManager.MinLength = checkpoint.MinLength;
                    _workManager.MaxLength = checkpoint.MaxLength;
                    // Restore charset from checkpoint
                    if (!string.IsNullOrEmpty(checkpoint.Charset))
                    {
                        RestoreCharsetFromString(checkpoint.Charset);
                    }
                    _workManager.UpdateCharset();

                    // Store checkpoint for resuming
                    _loadedCheckpoint = checkpoint;
                    _isResuming = true;

                    // Pre-restore GPU phase state for display
                    _currentGpuPhase = checkpoint.CurrentGpuPhase;
                    _totalGpuPhases = checkpoint.TotalGpuPhases;
                    _gpuTotalTestedCount = checkpoint.GpuTotalTestedCount;
                    _gpuOverallProgress = checkpoint.GpuOverallProgress;

                    // v1.7: Restore dictionary position for CPU resume
                    if (checkpoint.DictionaryLinePosition > 0)
                    {
                        _engine.ResumeFromLine = checkpoint.DictionaryLinePosition;
                        if (!string.IsNullOrEmpty(checkpoint.DictionaryPath))
                        {
                            _dictionaryPath = checkpoint.DictionaryPath;
                        }
                    }

                    Log($"Checkpoint loaded: {Path.GetFileName(checkpoint.ArchivePath)}");
                    Log($"Attack mode: {checkpoint.AttackMode}");
                    Log($"Progress - CPU: {checkpoint.CpuTestedCount:N0} (Line {checkpoint.DictionaryLinePosition:N0})");
                    Log($"Progress - GPU: {checkpoint.GpuOverallProgress:F1}% (Phase {checkpoint.CurrentGpuPhase}/{checkpoint.TotalGpuPhases})");
                    Log($"GPU Tested: {checkpoint.GpuTotalTestedCount:N0} passwords");
                    Log($"Elapsed: {TimeSpan.FromSeconds(checkpoint.ElapsedSeconds):hh\\:mm\\:ss}");
                    Log("Click START to resume from checkpoint");

                    // Show resume indicator
                    lblStatus.Text = "Ready to Resume";
                    lblStatus.Foreground = FindResource("AccentBrush") as SolidColorBrush;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Resume error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnDeleteCheckpoints_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Get list of available checkpoints
                var checkpoints = CheckpointManager.GetAllCheckpoints();

                if (checkpoints.Count == 0)
                {
                    MessageBox.Show("No checkpoints found.", "Delete Checkpoints",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // Confirm deletion
                var result = MessageBox.Show(
                    $"Found {checkpoints.Count} checkpoint(s).\n\n" +
                    $"Do you want to delete ALL checkpoints?\n\n" +
                    $"This action cannot be undone!",
                    "Delete All Checkpoints?",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    int deletedCount = 0;
                    foreach (var checkpoint in checkpoints)
                    {
                        CheckpointManager.DeleteCheckpoint(checkpoint.ArchivePath);
                        deletedCount++;
                    }

                    Log($"🗑️ Deleted {deletedCount} checkpoint(s)");
                    MessageBox.Show($"Successfully deleted {deletedCount} checkpoint(s).",
                        "Checkpoints Deleted",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    // Hide buttons if no checkpoints left
                    btnResume.Visibility = Visibility.Collapsed;
                    btnDeleteCheckpoints.Visibility = Visibility.Collapsed;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting checkpoints: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void SetAttackMode(string modeName)
        {
            // Parse attack mode name and set checkboxes accordingly
            if (string.IsNullOrEmpty(modeName)) return;

            // Reset all checkboxes first
            if (chkNumbers != null) chkNumbers.IsChecked = false;
            if (chkLowercase != null) chkLowercase.IsChecked = false;
            if (chkUppercase != null) chkUppercase.IsChecked = false;
            if (chkSpecial != null) chkSpecial.IsChecked = false;

            // Handle legacy mode names
            if (modeName.Contains("All") || modeName == "Smart Attack")
            {
                if (chkNumbers != null) chkNumbers.IsChecked = true;
                if (chkLowercase != null) chkLowercase.IsChecked = true;
                if (chkUppercase != null) chkUppercase.IsChecked = true;
                if (chkSpecial != null) chkSpecial.IsChecked = true;
            }
            else if (modeName.Contains("Alphanumeric"))
            {
                if (chkNumbers != null) chkNumbers.IsChecked = true;
                if (chkLowercase != null) chkLowercase.IsChecked = true;
                if (chkUppercase != null) chkUppercase.IsChecked = true;
            }
            else
            {
                // Parse individual parts
                if (modeName.Contains("Number")) chkNumbers.IsChecked = true;
                if (modeName.Contains("Lowercase") || modeName == "Lowercase") chkLowercase.IsChecked = true;
                if (modeName.Contains("Uppercase")) chkUppercase.IsChecked = true;
                if (modeName.Contains("Special")) chkSpecial.IsChecked = true;
            }
        }

        private void RestoreCharsetFromString(string charset)
        {
            if (string.IsNullOrEmpty(charset)) return;

            _workManager.UseNumbers = charset.Contains("0");
            _workManager.UseLowercase = charset.Contains("a");
            _workManager.UseUppercase = charset.Contains("A");
            _workManager.UseSpecial = charset.Contains("!");

            // Update UI checkboxes if they exist
            if (chkNumbers != null) chkNumbers.IsChecked = _workManager.UseNumbers;
            if (chkLowercase != null) chkLowercase.IsChecked = _workManager.UseLowercase;
            if (chkUppercase != null) chkUppercase.IsChecked = _workManager.UseUppercase;
            if (chkSpecial != null) chkSpecial.IsChecked = _workManager.UseSpecial;
        }

        /// <summary>
        /// Get AttackMode from checkboxes - always uses progressive brute force based on selected charset
        /// </summary>
        private AttackMode GetAttackModeFromCheckboxes()
        {
            // Always use progressive brute force with the selected charset
            // The charset is determined by the checkboxes, not by the attack mode enum
            bool hasNumbers = chkNumbers?.IsChecked == true;
            bool hasLower = chkLowercase?.IsChecked == true;
            bool hasUpper = chkUppercase?.IsChecked == true;
            bool hasSpecial = chkSpecial?.IsChecked == true;

            // Return most appropriate mode based on selection for GPU/Hashcat compatibility
            if (hasNumbers && !hasLower && !hasUpper && !hasSpecial)
                return AttackMode.BruteForceNumbers;
            if (hasLower && !hasNumbers && !hasUpper && !hasSpecial)
                return AttackMode.BruteForceLowercase;
            if ((hasNumbers || hasLower || hasUpper) && !hasSpecial)
                return AttackMode.BruteForceAlphanumeric;

            // Default to all characters (includes special)
            return AttackMode.BruteForceAll;
        }

        /// <summary>
        /// Build charset string from checkboxes
        /// </summary>
        private string GetCharsetFromCheckboxes()
        {
            var sb = new StringBuilder();
            if (chkNumbers?.IsChecked == true) sb.Append("0123456789");
            if (chkLowercase?.IsChecked == true) sb.Append("abcdefghijklmnopqrstuvwxyz");
            if (chkUppercase?.IsChecked == true) sb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            if (chkSpecial?.IsChecked == true) sb.Append("!@#$%^&*()_+-=");
            return sb.ToString();
        }

        private void CheckForCheckpointsOnStartup()
        {
            try
            {
                var checkpoints = CheckpointManager.GetAllCheckpoints();
                if (checkpoints.Count > 0)
                {
                    // Show resume and delete buttons
                    btnResume.Visibility = Visibility.Visible;
                    btnDeleteCheckpoints.Visibility = Visibility.Visible;
                    Log($"Found {checkpoints.Count} saved checkpoint(s). Click RESUME to continue or 🗑️ to delete all.");
                }
            }
            catch { }
        }

        #region Dynamic Worker Allocation

        /// <summary>
        /// Calculate work allocation based on worker speeds
        /// GPU is assumed to be 20x faster than CPU by default
        /// </summary>
        private (long cpuStart, long cpuEnd, long gpuStart, long gpuEnd)
            CalculateDynamicAllocation(long totalRemaining, long globalStart, bool useCpu, bool useGpu)
        {
            if (!useCpu && !useGpu)
                return (0, 0, 0, 0);

            // If only one worker, give all work to that worker
            if (useCpu && !useGpu)
            {
                return (globalStart, globalStart + totalRemaining, 0, 0);
            }
            if (!useCpu && useGpu)
            {
                return (0, 0, globalStart, globalStart + totalRemaining);
            }

            // Both workers - calculate speed ratio
            double cpuSpeed = _cpuSpeed > 0 ? _cpuSpeed : 1;
            double gpuSpeed = _gpuSpeed > 0 ? _gpuSpeed : 20; // Assume GPU is 20x faster

            double totalSpeed = cpuSpeed + gpuSpeed;
            double cpuRatio = cpuSpeed / totalSpeed;

            long cpuWork = (long)(totalRemaining * cpuRatio);
            long gpuWork = totalRemaining - cpuWork;

            long cpuStart = globalStart;
            long cpuEnd = cpuStart + cpuWork;
            long gpuStart = cpuEnd;
            long gpuEnd = globalStart + totalRemaining;

            return (cpuStart, cpuEnd, gpuStart, gpuEnd);
        }

        /// <summary>
        /// Allocate work ranges to CPU and GPU workers
        /// </summary>
        private void AllocateWorkRanges(bool useCpu, bool useGpu)
        {
            long globalProgress = Math.Max(_cpuCurrentPosition, _gpuCurrentPosition);
            long remaining = _totalPasswordSpace - globalProgress;

            if (!_isReconfiguring)
            {
                // First start or normal resume
                if (useCpu && useGpu)
                {
                    // Hybrid: dynamic split
                    var allocation = CalculateDynamicAllocation(remaining, globalProgress, useCpu, useGpu);
                    _cpuStartPosition = allocation.cpuStart;
                    _cpuEndPosition = allocation.cpuEnd;
                    _gpuStartPosition = allocation.gpuStart;
                    _gpuEndPosition = allocation.gpuEnd;

                    double cpuRatio = remaining > 0 ? (double)(_cpuEndPosition - _cpuStartPosition) / remaining * 100 : 0;
                    double gpuRatio = remaining > 0 ? (double)(_gpuEndPosition - _gpuStartPosition) / remaining * 100 : 0;

                    Log($"Work allocation (speed-based):");
                    Log($"  CPU: {_cpuStartPosition:N0} -> {_cpuEndPosition:N0} ({(_cpuEndPosition - _cpuStartPosition):N0} passwords, {cpuRatio:F1}%)");
                    Log($"  GPU: {_gpuStartPosition:N0} -> {_gpuEndPosition:N0} ({(_gpuEndPosition - _gpuStartPosition):N0} passwords, {gpuRatio:F1}%)");
                }
                else if (useCpu)
                {
                    // CPU only
                    _cpuStartPosition = globalProgress;
                    _cpuEndPosition = _totalPasswordSpace;
                    _gpuStartPosition = 0;
                    _gpuEndPosition = 0;
                    Log($"CPU-only mode: {_cpuStartPosition:N0} -> {_cpuEndPosition:N0} ({(_cpuEndPosition - _cpuStartPosition):N0} passwords)");
                }
                else if (useGpu)
                {
                    // GPU only
                    _cpuStartPosition = 0;
                    _cpuEndPosition = 0;
                    _gpuStartPosition = globalProgress;
                    _gpuEndPosition = _totalPasswordSpace;
                    Log($"GPU-only mode: {_gpuStartPosition:N0} -> {_gpuEndPosition:N0} ({(_gpuEndPosition - _gpuStartPosition):N0} passwords)");
                }
            }
            else
            {
                // Reconfiguring - reallocate remaining work
                Log($"⚙️ Worker configuration changed - reallocating work...");
                Log($"   Completed: {globalProgress:N0}, Remaining: {remaining:N0}");

                var allocation = CalculateDynamicAllocation(remaining, globalProgress, useCpu, useGpu);
                _cpuStartPosition = allocation.cpuStart;
                _cpuEndPosition = allocation.cpuEnd;
                _gpuStartPosition = allocation.gpuStart;
                _gpuEndPosition = allocation.gpuEnd;

                if (useCpu && useGpu)
                {
                    double cpuSpeed = _cpuSpeed > 0 ? _cpuSpeed : 1;
                    double gpuSpeed = _gpuSpeed > 0 ? _gpuSpeed : 20;
                    double ratio = gpuSpeed / cpuSpeed;
                    Log($"   Speed ratio: CPU={cpuSpeed:N0}/s, GPU={gpuSpeed:N0}/s (1:{ratio:F1})");
                }

                Log($"New allocation:");
                if (useCpu)
                    Log($"  CPU: {_cpuStartPosition:N0} -> {_cpuEndPosition:N0} ({(_cpuEndPosition - _cpuStartPosition):N0} passwords)");
                if (useGpu)
                    Log($"  GPU: {_gpuStartPosition:N0} -> {_gpuEndPosition:N0} ({(_gpuEndPosition - _gpuStartPosition):N0} passwords)");

                _isReconfiguring = false;
            }
        }

        #endregion

        #endregion
    }

    // Firefly particle class
    public class Firefly
    {
        public double X { get; set; }
        public double Y { get; set; }
        public double VelocityX { get; set; }
        public double VelocityY { get; set; }
        public double Size { get; set; }
        public double Opacity { get; set; }
        public double OpacityDirection { get; set; }
        public double HueOffset { get; set; }
        public double HueSpeed { get; set; }
        public Ellipse Visual { get; set; }
    }
}
