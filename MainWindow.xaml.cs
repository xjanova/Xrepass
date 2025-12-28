using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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
        private long _gpuProgress;  // GPU progress percentage (0-100)
        private long _gpuTestedCount;  // GPU passwords actually tested
        private long _totalPossiblePasswords;  // Total passwords for entire job (CPU + GPU range)
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
        private static readonly string SevenZ2JohnPath = Path.Combine(ToolsDir, "7z2john.pl");
        private static readonly string Rar2JohnPath = Path.Combine(ToolsDir, "rar2john.py");
        private static readonly string TestedPasswordsFile = Path.Combine(AppDataDir, "tested_passwords.txt");
        private static readonly string SettingsFile = Path.Combine(AppDataDir, "settings.txt");
        private static readonly HttpClient _httpClient = new HttpClient() { Timeout = TimeSpan.FromSeconds(30) }; // 30s timeout for large downloads

        // Tool paths from settings
        private string _7z2johnPath;
        private string _perlPath;
        private string _rar2johnPath;
        private string _pythonPath;

        // Skip already tested passwords
        private ConcurrentDictionary<string, byte> _testedPasswords = new ConcurrentDictionary<string, byte>();

        // Firefly animation
        private List<Firefly> _fireflies = new List<Firefly>();
        private DispatcherTimer _fireflyTimer;
        private Random _fireflyRandom = new Random();

        // Work chunk manager
        private WorkChunkManager _workManager;

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

        // Hash detection cancellation
        private System.Threading.CancellationTokenSource _hashDetectionCts;

        public MainWindow()
        {
            InitializeComponent();
            InitializeEngine();
            InitializeTimer();
            InitializeDatabase();
            LoadTestedPasswords();
            LoadSettings();

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

            // Check and download Hashcat on startup
            _ = CheckAndDownloadHashcatAsync();

            Log("Select an archive file and choose attack mode to begin.");

            // Initialize firefly animation
            InitializeFireflies();

            // Check for saved checkpoints
            CheckForCheckpointsOnStartup();

            // Register closing event to cleanup
            this.Closing += MainWindow_Closing;
        }

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Cleanup all running processes and tasks
            try
            {
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
                        }
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
                Dispatcher.Invoke(() =>
                {
                    txtLog.AppendText(msg + Environment.NewLine);
                    txtLog.CaretIndex = txtLog.Text.Length;
                    txtLog.ScrollToEnd();
                });
            };

            _engine.OnPasswordTested += (pwd) =>
            {
                SaveTestedPassword(pwd);
                Dispatcher.Invoke(() =>
                {
                    lblCurrentPwd.Text = pwd;
                });
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
                Dispatcher.Invoke(() =>
                {
                    lblStatus.Text = status;
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

                // Get hash info (async - ไม่บล็อก UI) - timeout 5 วินาที
                Log($"Detecting archive format for: {fi.Name} ({fi.Length} bytes)");
                var hashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text, timeoutMs: 5000);
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
            // Stop everything
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
                    if (_workManager != null)
                    {
                        var cpuStats = _workManager.CpuStats;
                        double chunkProgress = cpuStats.GetChunkProgressPercent();
                        string action = cpuRunning ? "Testing passwords..." : "Idle";

                        // คำนวณ ETA
                        long cpuRemaining = (long)(_workManager.TotalPasswords - cpuTestedCount);
                        if (cpuRemaining < 0) cpuRemaining = 0;
                        string cpuEta = CalculateEta(cpuRemaining, _cpuSpeed);

                        UpdateCpuProgress(cpuStats.CurrentPhase > 0 ? cpuStats.CurrentPhase : 1,
                                        cpuTestedCount, chunkProgress,
                                        cpuTestedCount, (long)_workManager.TotalPasswords, action, cpuEta);
                    }
                }

                // Calculate CPU progress based on its assigned work range
                double cpuProgress = 0;
                if (_engine.TotalPossiblePasswords > 0)
                {
                    cpuProgress = (double)cpuTestedCount / _engine.TotalPossiblePasswords * 100;
                    cpuProgress = Math.Min(cpuProgress, 100);
                }

                // Update CPU progress bars
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
                if (_workManager != null && gpuRunning)
                {
                    var gpuStats = _workManager.GpuStats;
                    string gpuAction = gpuRunning ? "Running Hashcat..." : "Idle";

                    // คำนวณ ETA สำหรับ GPU
                    long gpuRemaining = (long)(_workManager.TotalPasswords - _gpuTestedCount);
                    if (gpuRemaining < 0) gpuRemaining = 0;
                    string gpuEta = CalculateEta(gpuRemaining, _gpuSpeed);

                    UpdateGpuProgress(gpuStats.CurrentPhase > 0 ? gpuStats.CurrentPhase : 1,
                                     _gpuTestedCount, gpuProgress,
                                     _gpuTestedCount, (long)_workManager.TotalPasswords, gpuAction, gpuEta);
                }

                // Calculate OVERALL progress
                // Total tested = CPU tested + GPU tested
                // Progress = (total tested / total possible) * 100
                long totalTestedCount = cpuTestedCount + _gpuTestedCount;
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

                // Update top stats
                lblSpeedTop.Text = $"{combinedSpeed:N0} /sec";
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

            // ลบ checkpoint เก่า (เพราะเปิดไฟล์ใหม่ = เริ่มต้นใหม่)
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                CheckpointManager.DeleteCheckpoint(path);
                _loadedCheckpoint = null;
                _isResuming = false;
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
                    // RAR - Check if rar2john + Python available for GPU support
                    bool hasRar2John = !string.IsNullOrEmpty(_rar2johnPath) && File.Exists(_rar2johnPath);
                    bool hasPython = !string.IsNullOrEmpty(_pythonPath) && File.Exists(_pythonPath);
                    bool canUseGpuForRar = hasRar2John && hasPython;

                    chkCpu.IsEnabled = true;
                    chkCpu.IsChecked = true;  // Enable CPU by default
                    chkGpu.IsEnabled = true;  // Always enable GPU for RAR (will auto-download tools if needed)

                    if (canUseGpuForRar)
                    {
                        // GPU ready - tools already installed
                        chkGpu.IsChecked = true;  // Auto-enable GPU

                        Log($"⚠️ RAR encryption detected");
                        Log($"   CPU mode: ✓ Available (uses WinRAR verification)");
                        Log($"   GPU mode: ✓ Ready (rar2john.py + Python installed)");
                        Log($"   💡 GPU will extract hash using rar2john, then crack with Hashcat");
                    }
                    else
                    {
                        // GPU available but tools not installed yet
                        // Keep GPU unchecked by default, but user can enable it
                        chkGpu.IsChecked = false;

                        Log($"⚠️ RAR encryption detected");
                        Log($"   CPU mode: ✓ Available (uses WinRAR verification)");
                        Log($"   GPU mode: ⚙️ Available (will auto-download tools if enabled)");

                        if (!hasRar2John && !hasPython)
                            Log($"   💡 Enable GPU to auto-download rar2john.py + Python Portable");
                        else if (!hasRar2John)
                            Log($"   💡 Enable GPU to auto-download rar2john.py");
                        else if (!hasPython)
                            Log($"   💡 Enable GPU to auto-download Python Portable");
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
                _gpuProgress = 0;
                _totalPossiblePasswords = 0;
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
            _engine.EnableUtf8 = chkUtf8.IsChecked == true;

            if (_engine.EnableUtf8)
            {
                Log("⚠️ UTF-8 mode enabled - รองรับภาษาไทยและภาษาอื่นๆ (ช้ากว่าปกติมาก)");
            }

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
                _isResuming = false; // Clear resume flag
            }
            else
            {
                _stopwatch.Restart();
            }
            _updateTimer.Start();
            _checkpointTimer.Start(); // Start auto-save checkpoint

            Log("");
            if (useCpu && useGpu)
            {
                Log("=== HYBRID ATTACK (CPU + GPU) ===");
                GpuLog("=== HYBRID ATTACK (CPU + GPU) ===");
            }
            else if (useGpu)
            {
                GpuLog("=== GPU ATTACK MODE ===");
            }
            else
            {
                Log("=== CPU ATTACK MODE ===");
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

        private void ChkUtf8_Checked(object sender, RoutedEventArgs e)
        {
            // UTF-8 เพิ่มอักขระมาก → คำนวณความเป็นไปได้ใหม่
            UpdateCharsetInfo();
            Log("🌏 UTF-8 enabled - รองรับภาษาไทยและภาษาอื่นๆ (ช้ากว่าปกติ)");
        }

        private void ChkUtf8_Unchecked(object sender, RoutedEventArgs e)
        {
            // ปิด UTF-8 → คำนวณความเป็นไปได้ใหม่
            UpdateCharsetInfo();
            Log("UTF-8 disabled - ใช้ ASCII เท่านั้น");
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

            // Extract hash using HashFormatDetector (auto-detects format and mode)
            var hashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text);

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

                Dispatcher.Invoke(() => lblGpuStatus.Text = "Hashcat Not Found");

                // Still extract and show hash for manual use
                GpuLog("");
                GpuLog("=== EXTRACTING HASH FOR MANUAL USE ===");
                var manualHashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text);
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
            GpuLog("Extracting hash from archive...");
            var hashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text);

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
                    // Check if Perl is available before retrying
                    if (!HashFormatDetector.IsPerlAvailable() && hashInfo.ErrorMessage.Contains("Perl"))
                    {
                        GpuLog("Perl not found - checking for installation...");

                        // Check if we have Perl path
                        bool hasPerl = false;
                        if (!string.IsNullOrEmpty(_perlPath) && File.Exists(_perlPath))
                        {
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
                            GpuLog("Strawberry Perl not found - downloading...");
                            await DownloadStrawberryPerlAsync();

                            // Check if download succeeded
                            if (File.Exists(PerlExe))
                            {
                                _perlPath = PerlExe;
                                HashFormatDetector.SetPerlPath(_perlPath);
                                hasPerl = true;
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
                    }

                    // Retry extraction if we have both tools
                    if (hashInfo.IsValid || !hashInfo.ErrorMessage.Contains("Perl"))
                    {
                        GpuLog("Retrying hash extraction with 7z2john...");
                        hashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text);
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
                    GpuLog("rar2john.py not found - downloading...");
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
                    // Check if Python is available before retrying
                    if (!HashFormatDetector.IsPythonAvailable() && hashInfo.ErrorMessage.Contains("Python"))
                    {
                        GpuLog("Python not found - checking for installation...");

                        // Check if we have Python path
                        bool hasPython = false;
                        if (!string.IsNullOrEmpty(_pythonPath) && File.Exists(_pythonPath))
                        {
                            hasPython = true;
                            GpuLog($"Using Python from: {_pythonPath}");
                        }
                        else if (File.Exists(PythonExe))
                        {
                            _pythonPath = PythonExe;
                            HashFormatDetector.SetPythonPath(_pythonPath);
                            hasPython = true;
                            GpuLog($"Using Python from: {PythonExe}");
                        }
                        else
                        {
                            // Download Python Portable
                            GpuLog("Python Portable not found - downloading...");
                            await DownloadPythonPortableAsync();

                            // Check if download succeeded
                            if (File.Exists(PythonExe))
                            {
                                _pythonPath = PythonExe;
                                HashFormatDetector.SetPythonPath(_pythonPath);
                                hasPython = true;
                            }
                        }

                        if (!hasPython)
                        {
                            GpuLog("⚠️ Failed to get Python - cannot extract hash from RAR");
                            GpuLog("Please install Python manually from: https://www.python.org/");
                            hashInfo = new HashFormatDetector.HashInfo
                            {
                                IsValid = false,
                                ErrorMessage = "Python installation required but auto-download failed"
                            };
                        }
                    }

                    // Retry extraction if we have both tools
                    if (hashInfo.IsValid || !hashInfo.ErrorMessage.Contains("Python"))
                    {
                        GpuLog("Retrying hash extraction with rar2john...");
                        hashInfo = await HashFormatDetector.ExtractHashAsync(txtFilePath.Text);
                    }
                }
                else
                {
                    GpuLog("⚠️ Failed to get rar2john.py - cannot extract hash from RAR");
                }
            }

            // Check if hash extraction failed
            if (!hashInfo.IsValid)
            {
                GpuLog($"❌ ERROR: Could not extract hash");
                GpuLog($"   Type: {hashInfo.Type}");
                GpuLog($"   Message: {hashInfo.ErrorMessage}");
                GpuLog("");
                if (hashInfo.Type == HashFormatDetector.HashType.SevenZip)
                {
                    GpuLog("💡 7z2john requires Perl to be installed.");
                    GpuLog("   Install Strawberry Perl from: https://strawberryperl.com/");
                }
                else if (hashInfo.Type == HashFormatDetector.HashType.RAR3 || hashInfo.Type == HashFormatDetector.HashType.RAR5)
                {
                    GpuLog("💡 rar2john requires Python to be installed.");
                    GpuLog("   Download Python Portable from Settings or install from: https://www.python.org/");
                }
                else
                {
                    GpuLog("💡 Tip: For RAR and 7-Zip files, you may need external tools:");
                    GpuLog("   - RAR: Use 'rar2john.py' (requires Python)");
                    GpuLog("   - 7z:  Use '7z2john.pl' (requires Perl)");
                }
                Dispatcher.Invoke(() => lblGpuStatus.Text = "Hash Error");
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
                Dispatcher.Invoke(() => lblGpuStatus.Text = "Not Supported");
                return;
            }

            GpuLog($"✓ Detected: {hashInfo.Type}");
            GpuLog($"  Hashcat Mode: {hashInfo.HashcatMode} ({HashFormatDetector.GetHashcatModeDescription(hashInfo.HashcatMode)})");
            GpuLog($"  Hash extracted successfully");

            // Write hash to temp file
            string hashFile = Path.Combine(Path.GetTempPath(), $"archive_hash_{Guid.NewGuid():N}.txt");
            File.WriteAllText(hashFile, hashInfo.Hash);

            // Log full hash for debugging (important for troubleshooting)
            GpuLog($"  Hash: {hashInfo.Hash}");
            GpuLog($"  Saved to: {hashFile}");

            GpuLog("");
            GpuLog("=== GPU ATTACK (Hashcat) ===");

            _gpuCts = new CancellationTokenSource();
            _gpuSpeed = 0;

            Dispatcher.Invoke(() => lblGpuStatus.Text = "Starting...");

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
            // Order: digits first (most common for simple passwords), then letters
            var hashcatCharset = new StringBuilder();
            if (hasNumbers) hashcatCharset.Append("?d");
            if (hasLower) hashcatCharset.Append("?l");
            if (hasUpper) hashcatCharset.Append("?u");
            if (hasSpecial) hashcatCharset.Append("?s");

            if (hashcatCharset.Length == 0)
            {
                GpuLog("ERROR: No charset selected!");
                return;
            }

            // Determine mask and attack args based on selected charset
            string charsetDef = hashcatCharset.ToString();

            // Single charset - use built-in mask characters
            if (charsetDef == "?d")
            {
                // Numbers only
                mask = string.Concat(System.Linq.Enumerable.Repeat("?d", maxLen));
                attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
            }
            else if (charsetDef == "?l")
            {
                // Lowercase only
                mask = string.Concat(System.Linq.Enumerable.Repeat("?l", maxLen));
                attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
            }
            else if (charsetDef == "?u")
            {
                // Uppercase only
                mask = string.Concat(System.Linq.Enumerable.Repeat("?u", maxLen));
                attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
            }
            else if (charsetDef == "?d?l" || charsetDef == "?d?u" || charsetDef == "?l?u" ||
                     charsetDef == "?d?l?u" || charsetDef == "?d?l?u?s")
            {
                // Multiple charsets - use custom charset -1
                attackArgs = $"-a 3 -1 {charsetDef} --increment --increment-min {minLen} --increment-max {maxLen}";
                mask = string.Concat(System.Linq.Enumerable.Repeat("?1", maxLen));
            }
            else
            {
                // Any other combination - use custom charset -1
                attackArgs = $"-a 3 -1 {charsetDef} --increment --increment-min {minLen} --increment-max {maxLen}";
                mask = string.Concat(System.Linq.Enumerable.Repeat("?1", maxLen));
            }

            // Use the auto-detected hashcat mode from HashFormatDetector
            string hashcatMode = hashInfo.HashcatMode.ToString();

            string outputFile = Path.Combine(Path.GetTempPath(), $"hashcat_found_{Guid.NewGuid():N}.txt");
            // -w 3 = high workload (faster), -O = optimized kernels, -D 1,2 = use CPU+GPU devices
            string args = $"-m {hashcatMode} {attackArgs} -w 3 -O -o \"{outputFile}\" --potfile-disable --status --status-timer=1 \"{hashFile}\" {mask}";

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
                        Dispatcher.Invoke(() =>
                        {
                            // Log all output
                            GpuLog(e.Data);

                            // Parse speed from hashcat output
                            // Format: "Speed.#1.........:  1234.5 MH/s"
                            if (e.Data.Contains("Speed."))
                            {
                                var match = Regex.Match(e.Data, @"(\d+\.?\d*)\s*(k|M|G)?H/s");
                                if (match.Success)
                                {
                                    double speed = double.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                                    string unit = match.Groups[2].Value;
                                    if (unit == "k") speed *= 1000;
                                    else if (unit == "M") speed *= 1000000;
                                    else if (unit == "G") speed *= 1000000000;
                                    _gpuSpeed = (long)speed;
                                    lblGpuSpeed.Text = $"{_gpuSpeed:N0} /sec";
                                }
                            }

                            // Parse progress from hashcat output
                            // Format: "Progress.........: 123456/999999 (12.35%)"
                            if (e.Data.Contains("Progress"))
                            {
                                var match = Regex.Match(e.Data, @"Progress[.\s]*:\s*(\d+)/(\d+)\s*\((\d+\.?\d*)%\)");
                                if (match.Success)
                                {
                                    // GPU tested count = current progress number from hashcat
                                    _gpuTestedCount = long.Parse(match.Groups[1].Value);
                                    long gpuTotal = long.Parse(match.Groups[2].Value);
                                    double percent = double.Parse(match.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture);
                                    _gpuProgress = (long)percent;

                                    // Update GPU status with progress
                                    lblGpuStatus.Text = $"Running ({percent:F1}%)";
                                }
                            }

                            // Parse GPU temperature from hashcat output
                            // Format: "Hardware.Mon.#1..: Temp: 65c Util: 99% Core:1950MHz Mem:7000MHz Bus:16"
                            // Or: "Temp.............:  65c"
                            if (e.Data.Contains("Temp") && (e.Data.Contains("c") || e.Data.Contains("°")))
                            {
                                var match = Regex.Match(e.Data, @"Temp[.\s:]*(\d+)\s*[c°]", RegexOptions.IgnoreCase);
                                if (match.Success)
                                {
                                    _gpuTemp = int.Parse(match.Groups[1].Value);
                                }
                            }

                            // Update status
                            if (e.Data.Contains("Status.."))
                            {
                                if (e.Data.Contains("Running")) { /* already updated above */ }
                                else if (e.Data.Contains("Exhausted")) lblGpuStatus.Text = "Exhausted";
                                else if (e.Data.Contains("Cracked")) lblGpuStatus.Text = "Cracked!";
                            }
                        });
                    }
                };

                _hashcatProcess.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data) && !_passwordFound)
                    {
                        Dispatcher.Invoke(() => GpuLog($"[ERR] {e.Data}"));
                    }
                };

                GpuLog("Starting hashcat process...");
                GpuLog($"Executable: {txtHashcatPath.Text}");

                _hashcatProcess.Start();
                GpuLog($"Hashcat PID: {_hashcatProcess.Id}");

                _hashcatProcess.BeginOutputReadLine();
                _hashcatProcess.BeginErrorReadLine();

                Dispatcher.Invoke(() => lblGpuStatus.Text = "Compiling kernels...");

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
                            Dispatcher.Invoke(() => GpuLog($"[DEBUG] Checking output file... (check #{checkCount})"));
                        }

                        // Check if password was found
                        if (File.Exists(outputFile) && new FileInfo(outputFile).Length > 0)
                        {
                            string result = File.ReadAllText(outputFile).Trim();
                            Dispatcher.Invoke(() => GpuLog($"[DEBUG] Output file content: {result}"));

                            if (!string.IsNullOrEmpty(result))
                            {
                                // Format for WinZip: $zip2$...*$/zip2$:password
                                // We need to find the LAST colon after $/zip2$
                                int endMarkerIdx = result.IndexOf("$/zip2$");
                                int colonIdx = endMarkerIdx > 0 ? result.IndexOf(':', endMarkerIdx) : result.LastIndexOf(':');

                                if (colonIdx > 0 && colonIdx < result.Length - 1)
                                {
                                    string foundPwd = result.Substring(colonIdx + 1);

                                    // Password found by GPU!
                                    _passwordFound = true;
                                    _foundPassword = foundPwd;

                                    // Cancel CPU
                                    _masterCts?.Cancel();
                                    _engine.Stop();

                                    Dispatcher.Invoke(() =>
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
                switch (exitCode)
                {
                    case 0:
                        GpuLog("[GPU] Status: CRACKED - Password found!");
                        // Double check output file
                        if (File.Exists(outputFile))
                        {
                            string finalResult = File.ReadAllText(outputFile).Trim();
                            GpuLog($"[GPU] Output file: {finalResult}");
                        }
                        break;
                    case 1:
                        GpuLog("[GPU] Status: EXHAUSTED - All passwords tried, no match found");
                        GpuLog("[GPU] This means the password is NOT in the tested range/charset");
                        break;
                    case -1:
                    case 255:
                        GpuLog("[GPU] Status: ERROR - Hashcat encountered an error");
                        GpuLog("[GPU] Check the log above for error details");
                        GpuLog("[GPU] Common issues:");
                        GpuLog("   - Invalid hash format");
                        GpuLog("   - GPU driver issues");
                        GpuLog("   - Insufficient memory");
                        break;
                    default:
                        GpuLog($"[GPU] Status: Unknown exit code {exitCode}");
                        break;
                }

                if (!_passwordFound)
                {
                    GpuLog("[GPU] Hashcat finished - password NOT found by GPU");
                    Dispatcher.Invoke(() => lblGpuStatus.Text = exitCode == 1 ? "Exhausted" : (exitCode == 0 ? "Cracked?" : "Error"));
                }
            }
            catch (Exception ex)
            {
                GpuLog($"[ERROR] {ex.Message}");
                Dispatcher.Invoke(() => lblGpuStatus.Text = "Error");
            }
            finally
            {
                _gpuSpeed = 0;
                try { File.Delete(hashFile); } catch { }
            }
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
            Dispatcher.Invoke(() =>
            {
                txtGpuLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                txtGpuLog.CaretIndex = txtGpuLog.Text.Length;
                txtGpuLog.ScrollToEnd();
            });
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
                    Dispatcher.Invoke(() =>
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
                Dispatcher.Invoke(() =>
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
                                    Dispatcher.Invoke(() => Log($"Download progress: {progress}%"));
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

                    Dispatcher.Invoke(() =>
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
            // Strawberry Perl Portable (64-bit)
            const string url = "https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit-portable.zip";

            try
            {
                GpuLog("Downloading Strawberry Perl Portable (64-bit, ~100MB)...");
                GpuLog("This may take 1-2 minutes depending on your connection...");
                Directory.CreateDirectory(ToolsDir);

                var downloadPath = Path.Combine(ToolsDir, "strawberry-perl.zip");

                // Download with progress
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); // 5 min timeout
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

                GpuLog("Download complete. Extracting Perl...");

                // Extract using built-in ZipFile
                System.IO.Compression.ZipFile.ExtractToDirectory(downloadPath, PerlDir, true);

                // Clean up zip file
                File.Delete(downloadPath);

                // Set Perl path
                if (File.Exists(PerlExe))
                {
                    _perlPath = PerlExe;
                    HashFormatDetector.SetPerlPath(_perlPath);
                    SaveSettings();
                    GpuLog($"✅ Strawberry Perl installed successfully!");
                    GpuLog($"   Location: {PerlExe}");
                }
                else
                {
                    GpuLog($"⚠️ Perl extracted but perl.exe not found at expected location");
                }
            }
            catch (TaskCanceledException)
            {
                GpuLog($"❌ Download timeout (5min) - Check your internet connection");
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

        private async Task DownloadRar2JohnAsync()
        {
            const string url = "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/rar2john.py";

            try
            {
                GpuLog("Downloading rar2john.py from GitHub...");
                Directory.CreateDirectory(ToolsDir);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var response = await _httpClient.GetAsync(url, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    GpuLog($"❌ Failed to download - HTTP {response.StatusCode}");
                    return;
                }

                var content = await response.Content.ReadAsStringAsync(cts.Token);
                File.WriteAllText(Rar2JohnPath, content);

                _rar2johnPath = Rar2JohnPath;
                SaveSettings();

                GpuLog($"✅ rar2john.py downloaded successfully!");
                GpuLog($"   Location: {Rar2JohnPath}");
            }
            catch (TaskCanceledException)
            {
                GpuLog($"❌ Download timeout (30s) - Check your internet connection");
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
                        Dispatcher.Invoke(() =>
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
                Dispatcher.Invoke(() => lblCpuModel.Text = "Unknown CPU");
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
                        Dispatcher.Invoke(() =>
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
                        Dispatcher.Invoke(() => lblGpuModel.Text = "No GPU detected");
                        Log("🎮 GPU: No dedicated GPU detected");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Could not detect GPU: {ex.Message}");
                Dispatcher.Invoke(() => lblGpuModel.Text = "Unknown GPU");
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
            var settingsWindow = new SettingsWindow(txtHashcatPath.Text, true, _7z2johnPath, _perlPath);
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

        #region Firefly Animation

        private void InitializeFireflies()
        {
            // Create initial fireflies
            for (int i = 0; i < 25; i++)
            {
                CreateFirefly();
            }

            // Start animation timer (runs on separate thread-safe dispatcher priority)
            _fireflyTimer = new DispatcherTimer(DispatcherPriority.Render);
            _fireflyTimer.Interval = TimeSpan.FromMilliseconds(33); // ~30 FPS for smooth animation
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

            // UTF-8 mode adds Thai characters (roughly 87 Thai chars)
            if (chkUtf8.IsChecked == true)
            {
                charsetSize += 87;
            }

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
        /// อัปเดต CPU progress section
        /// </summary>
        private void UpdateCpuProgress(int phase, long checkedCount, double chunkProgress, long chunkCurrent, long chunkTotal, string action, string eta = "--")
        {
            Dispatcher.InvokeAsync(() =>
            {
                lblCpuPhase.Text = phase.ToString();
                lblCpuChecked.Text = FormatNumber(checkedCount);
                lblCpuChunkProgress.Text = $"{chunkProgress:F1}%";
                progressBarCpuChunk.Value = chunkProgress;
                lblCpuChunkInfo.Text = $"{FormatNumber(chunkCurrent)}/{FormatNumber(chunkTotal)}";
                lblCpuCurrentAction.Text = action;
                lblCpuEta.Text = eta;
            });
        }

        /// <summary>
        /// อัปเดต GPU progress section
        /// </summary>
        private void UpdateGpuProgress(int phase, long checkedCount, double chunkProgress, long chunkCurrent, long chunkTotal, string action, string eta = "--")
        {
            Dispatcher.InvokeAsync(() =>
            {
                lblGpuPhase.Text = phase.ToString();
                lblGpuChecked.Text = FormatNumber(checkedCount);
                lblGpuChunkProgress.Text = $"{chunkProgress:F1}%";
                progressBarGpuChunk.Value = chunkProgress;
                lblGpuChunkInfo.Text = $"{FormatNumber(chunkCurrent)}/{FormatNumber(chunkTotal)}";
                lblGpuCurrentAction.Text = action;
                lblGpuEta.Text = eta;
            });
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
                lblCpuPhase.Text = "0";
                lblCpuChecked.Text = "0";
                lblCpuChunkProgress.Text = "0%";
                progressBarCpuChunk.Value = 0;
                lblCpuChunkInfo.Text = "0/0";
                lblCpuCurrentAction.Text = "Idle";
                lblCpuEta.Text = "--";

                // GPU
                lblGpuPhase.Text = "0";
                lblGpuChecked.Text = "0";
                lblGpuChunkProgress.Text = "0%";
                progressBarGpuChunk.Value = 0;
                lblGpuChunkInfo.Text = "0/0";
                lblGpuCurrentAction.Text = "Idle";
                lblGpuEta.Text = "--";
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
                UpdateCpuProgress(_workManager?.CpuStats.CurrentPhase ?? 0,
                                 _workManager?.CpuStats.TotalTested ?? 0,
                                 100, 1, 1, "PASSWORD FOUND!");
            }
            else
            {
                GpuLog(message);
                UpdateGpuProgress(_workManager?.GpuStats.CurrentPhase ?? 0,
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

                    Log($"Checkpoint loaded: {Path.GetFileName(checkpoint.ArchivePath)}");
                    Log($"Attack mode: {checkpoint.AttackMode}");
                    Log($"Progress - CPU: {checkpoint.CpuTestedCount:N0}, GPU: {checkpoint.GpuProgress}%");
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
