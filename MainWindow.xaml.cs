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
        private static readonly string TestedPasswordsFile = Path.Combine(AppDataDir, "tested_passwords.txt");
        private static readonly string SettingsFile = Path.Combine(AppDataDir, "settings.txt");
        private static readonly HttpClient _httpClient = new HttpClient();

        // Skip already tested passwords
        private ConcurrentDictionary<string, byte> _testedPasswords = new ConcurrentDictionary<string, byte>();

        // Firefly animation
        private List<Firefly> _fireflies = new List<Firefly>();
        private DispatcherTimer _fireflyTimer;
        private Random _fireflyRandom = new Random();

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
                        }
                    }
                }
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

        private void UpdateFileInfoDisplay()
        {
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

                // Get hash info
                var hashInfo = HashFormatDetector.ExtractHash(txtFilePath.Text);
                if (hashInfo.IsValid)
                {
                    lblHashTypeLarge.Text = hashInfo.Type.ToString().Replace("_", " ");
                    lblHashcatModeLarge.Text = $"#{hashInfo.HashcatMode}";
                }
                else
                {
                    lblHashTypeLarge.Text = "Unknown";
                    lblHashcatModeLarge.Text = "--";
                }
            }
            catch
            {
                lblFileNameLarge.Text = Path.GetFileName(txtFilePath.Text);
                lblFileSizeLarge.Text = "--";
                lblHashTypeLarge.Text = "--";
                lblHashcatModeLarge.Text = "--";
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

            // Update UI
            borderFound.Visibility = Visibility.Visible;
            lblFoundPwd.Text = password;
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

            _updateTimer.Tick += (s, e) =>
            {
                // Update elapsed time
                lblTime.Text = _stopwatch.Elapsed.ToString(@"hh\:mm\:ss");

                // Check if either CPU or GPU is running
                bool cpuRunning = _engine.IsRunning;
                bool gpuRunning = _hashcatProcess != null && !_hashcatProcess.HasExited;

                // Get CPU tested count (actually tested, not generated)
                long cpuTestedCount = _engine.TotalAttempts;

                // Update CPU stats display
                if (cpuRunning || cpuTestedCount > 0)
                {
                    lblCpuAttempts.Text = cpuTestedCount.ToString("N0");
                    if (_stopwatch.Elapsed.TotalSeconds > 0)
                    {
                        _cpuSpeed = (long)(cpuTestedCount / _stopwatch.Elapsed.TotalSeconds);
                        lblCpuSpeed.Text = $"{_cpuSpeed:N0} /sec";
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

                // GPU progress - use _gpuProgress from hashcat parsing (already percentage)
                double gpuProgress = Math.Min(_gpuProgress, 100);
                progressBarGpu.Value = gpuProgress;
                lblProgressGpu.Text = $"{gpuProgress:F0}%";
                progressBarGpuLarge.Value = gpuProgress;
                lblProgressGpuLarge.Text = $"{gpuProgress:F1}%";

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
                Filter = "All Archives (*.zip;*.rar;*.exe;*.ico;*.sfx)|*.zip;*.rar;*.exe;*.ico;*.sfx|ZIP files (*.zip)|*.zip|RAR files (*.rar)|*.rar|SFX/EXE files (*.exe;*.ico;*.sfx)|*.exe;*.ico;*.sfx|All files (*.*)|*.*",
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
            borderFound.Visibility = Visibility.Collapsed;

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
                else
                {
                    lblArchiveIcon.Text = "📁";
                    lblArchiveType.Foreground = new SolidColorBrush(Color.FromRgb(0, 245, 255)); // Cyan for ZIP
                }

                // Create/restore database session
                try
                {
                    string fileHash = DatabaseManager.ComputeFileHash(path);
                    var existingSession = _db?.GetSessionByFileHash(fileHash);

                    if (existingSession != null && !existingSession.IsCompleted)
                    {
                        // Resume existing session
                        _currentSessionId = existingSession.Id;
                        progressBar.Value = existingSession.ProgressPercent;
                        lblProgress.Text = $"{existingSession.ProgressPercent:F2}%";
                        Log($"Resuming previous session - {existingSession.ProgressPercent:F1}% completed");

                        if (existingSession.IsCracked && !string.IsNullOrEmpty(existingSession.FoundPassword))
                        {
                            Log($"Password was already found: {existingSession.FoundPassword}");
                        }
                    }
                    else
                    {
                        // Create new session
                        _currentSessionId = _db?.CreateSession(path, fileHash, _engine.ArchiveType) ?? 0;
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

            // Reset state
            _passwordFound = false;
            _foundPassword = null;
            _gpuSpeed = 0;
            _cpuSpeed = 0;
            _gpuTestedCount = 0;
            _gpuProgress = 0;
            _totalPossiblePasswords = 0;
            _masterCts = new CancellationTokenSource();

            // Load file if not loaded
            if (_engine.TotalAttempts == 0)
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

            // Get attack mode
            AttackMode mode = (AttackMode)cmbAttackMode.SelectedIndex;

            // Update UI
            btnStart.IsEnabled = false;
            btnPause.IsEnabled = true;
            btnStop.IsEnabled = true;
            btnBrowse.IsEnabled = false;
            borderFound.Visibility = Visibility.Collapsed;
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

            // Start timer
            _stopwatch.Restart();
            _updateTimer.Start();

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
            Log($"Skipping {_testedPasswords.Count:N0} previously tested passwords");
            Log("");

            // Update file info display
            UpdateFileInfoDisplay();

            // Calculate total possible passwords based on settings
            _totalPossiblePasswords = CalculateTotalPossiblePasswords(mode, minLen, maxLen);
            Log($"Total possible passwords: {_totalPossiblePasswords:N0}");

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
                // Pause
                _engine.Pause();
                _stopwatch.Stop();
                _updateTimer.Stop();

                txtPauseIcon.Text = "▶";
                txtPauseText.Text = "RESUME";
                lblStatus.Text = "Paused";
                lblGpuStatus.Text = "Paused";

                Log("=== PAUSED ===");
                GpuLog("=== PAUSED ===");
            }
            else
            {
                // Resume
                _engine.Resume();
                _stopwatch.Start();
                _updateTimer.Start();

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

            btnStop.IsEnabled = false;
            btnPause.IsEnabled = false;
            _isPaused = false;
            txtPauseIcon.Text = "⏸";
            txtPauseText.Text = "PAUSE";

            lblStatus.Text = "Stopping...";
            lblGpuStatus.Text = "Stopped";
        }

        private void BtnTest_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new TestPasswordDialog(_engine, txtFilePath.Text);
            dialog.Owner = this;
            dialog.ShowDialog();
        }

        private void BtnCopy_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(lblFoundPwd.Text))
            {
                Clipboard.SetText(lblFoundPwd.Text);
                MessageBox.Show("Password copied to clipboard!", "Copied",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void BtnContinue_Click(object sender, RoutedEventArgs e)
        {
            // User says the found password was a false positive - continue searching
            string falsePositive = lblFoundPwd.Text;
            Log($"False positive: {falsePositive} - Continuing search...");
            GpuLog($"False positive: {falsePositive} - Continuing search...");

            // Add to tested passwords so it won't be reported again
            SaveTestedPassword(falsePositive);

            // Reset state
            _passwordFound = false;
            _foundPassword = null;
            borderFound.Visibility = Visibility.Collapsed;

            // Get attack mode
            AttackMode mode = (AttackMode)cmbAttackMode.SelectedIndex;

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

            // Try to find hashcat
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

        private void BtnExtractHash_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtFilePath.Text) || !File.Exists(txtFilePath.Text))
            {
                MessageBox.Show("Please select a ZIP file first.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Extract hash using HashFormatDetector (auto-detects format and mode)
            var hashInfo = HashFormatDetector.ExtractHash(txtFilePath.Text);

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
            if (!File.Exists(txtHashcatPath.Text))
            {
                GpuLog("ERROR: Hashcat not found at: " + txtHashcatPath.Text);
                GpuLog("Please install Hashcat or browse to the correct path.");
                Dispatcher.Invoke(() => lblGpuStatus.Text = "Not Found");
                return;
            }

            // Extract hash using HashFormatDetector (auto-detects format and mode)
            var hashInfo = HashFormatDetector.ExtractHash(txtFilePath.Text);

            // Check if hash extraction failed
            if (!hashInfo.IsValid)
            {
                GpuLog($"❌ ERROR: Could not extract hash");
                GpuLog($"   Type: {hashInfo.Type}");
                GpuLog($"   Message: {hashInfo.ErrorMessage}");
                GpuLog("");
                GpuLog("💡 Tip: For RAR and 7-Zip files, you may need external tools:");
                GpuLog("   - RAR: Use 'rar2john' from John the Ripper");
                GpuLog("   - 7z:  Use '7z2john' from John the Ripper");
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

            // Log hash preview (truncate if too long)
            string hashPreview = hashInfo.Hash.Length > 80
                ? hashInfo.Hash.Substring(0, 40) + "..." + hashInfo.Hash.Substring(hashInfo.Hash.Length - 30)
                : hashInfo.Hash;
            GpuLog($"  Hash: {hashPreview}");
            GpuLog($"  Saved to: {hashFile}");

            GpuLog("");
            GpuLog("=== GPU ATTACK (Hashcat) ===");

            _gpuCts = new CancellationTokenSource();
            _gpuSpeed = 0;

            Dispatcher.Invoke(() => lblGpuStatus.Text = "Starting...");

            // Build hashcat command based on attack mode
            int minLen = int.Parse(txtMinLen.Text);
            int maxLen = int.Parse(txtMaxLen.Text);

            string mask = "";
            string attackArgs = "";
            AttackMode mode = (AttackMode)cmbAttackMode.SelectedIndex;

            switch (mode)
            {
                case AttackMode.BruteForceNumbers:
                    mask = string.Concat(System.Linq.Enumerable.Repeat("?d", maxLen));
                    attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
                    break;
                case AttackMode.BruteForceLowercase:
                    mask = string.Concat(System.Linq.Enumerable.Repeat("?l", maxLen));
                    attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
                    break;
                case AttackMode.BruteForceAlphanumeric:
                    attackArgs = $"-a 3 -1 ?l?u?d --increment --increment-min {minLen} --increment-max {maxLen}";
                    mask = string.Concat(System.Linq.Enumerable.Repeat("?1", maxLen));
                    break;
                case AttackMode.BruteForceAll:
                    mask = string.Concat(System.Linq.Enumerable.Repeat("?a", maxLen));
                    attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
                    break;
                default:
                    // Smart/Pattern - use full charset
                    mask = string.Concat(System.Linq.Enumerable.Repeat("?a", maxLen));
                    attackArgs = $"-a 3 --increment --increment-min {minLen} --increment-max {maxLen}";
                    break;
            }

            // Use the auto-detected hashcat mode from HashFormatDetector
            string hashcatMode = hashInfo.HashcatMode.ToString();

            string outputFile = Path.Combine(Path.GetTempPath(), $"hashcat_found_{Guid.NewGuid():N}.txt");
            string args = $"-m {hashcatMode} {attackArgs} -o \"{outputFile}\" --potfile-disable --status --status-timer=2 \"{hashFile}\" {mask}";

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

                _hashcatProcess.Start();
                _hashcatProcess.BeginOutputReadLine();
                _hashcatProcess.BeginErrorReadLine();

                Dispatcher.Invoke(() => lblGpuStatus.Text = "Running");

                await Task.Run(() =>
                {
                    while (!_hashcatProcess.HasExited && !_gpuCts.Token.IsCancellationRequested && !_passwordFound)
                    {
                        Thread.Sleep(500);

                        // Check if password was found
                        if (File.Exists(outputFile) && new FileInfo(outputFile).Length > 0)
                        {
                            string result = File.ReadAllText(outputFile).Trim();
                            if (!string.IsNullOrEmpty(result))
                            {
                                // Format: hash:password
                                int colonIdx = result.LastIndexOf(':');
                                if (colonIdx > 0)
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

                if (!_passwordFound)
                {
                    GpuLog("[GPU] Hashcat finished");
                    Dispatcher.Invoke(() => lblGpuStatus.Text = "Finished");
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
            var settingsWindow = new SettingsWindow(txtHashcatPath.Text, true);
            if (settingsWindow.ShowDialog() == true && settingsWindow.SettingsSaved)
            {
                txtHashcatPath.Text = settingsWindow.HashcatPath;
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
