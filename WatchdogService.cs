using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace ZipCrackerUI
{
    /// <summary>
    /// Watchdog Service - ตรวจจับโปรแกรมค้างและจัดการ hashcat process
    /// ทำงานใน background thread แยกต่างหาก
    /// </summary>
    public class WatchdogService : IDisposable
    {
        private static WatchdogService _instance;
        private static readonly object _lock = new object();

        // Heartbeat tracking
        private DateTime _lastHeartbeat;
        private readonly TimeSpan _heartbeatTimeout = TimeSpan.FromSeconds(30);
        private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(5);

        // Process tracking
        private int? _hashcatProcessId;
        private int _mainProcessId;
        private string _currentArchivePath;

        // Threading
        private Thread _watchdogThread;
        private volatile bool _isRunning;
        private readonly ManualResetEvent _stopEvent = new ManualResetEvent(false);

        // Checkpoint callback
        private Action _saveCheckpointAction;
        private Func<CheckpointData> _getCheckpointDataFunc;

        // Logging
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "X-Repass", "watchdog.log");

        private WatchdogService()
        {
            _mainProcessId = Process.GetCurrentProcess().Id;
            _lastHeartbeat = DateTime.Now;
        }

        /// <summary>
        /// Get singleton instance
        /// </summary>
        public static WatchdogService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new WatchdogService();
                        }
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// Start watchdog service
        /// </summary>
        public void Start()
        {
            if (_isRunning) return;

            _isRunning = true;
            _stopEvent.Reset();
            _lastHeartbeat = DateTime.Now;

            // Clean up any orphaned hashcat processes from previous crash
            CleanupOrphanedHashcatProcesses();

            _watchdogThread = new Thread(WatchdogLoop)
            {
                Name = "WatchdogService",
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _watchdogThread.Start();

            Log("Watchdog service started");
        }

        /// <summary>
        /// Stop watchdog service
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;
            _stopEvent.Set();

            // Wait for thread to finish
            if (_watchdogThread != null && _watchdogThread.IsAlive)
            {
                _watchdogThread.Join(2000);
            }

            Log("Watchdog service stopped");
        }

        /// <summary>
        /// Update heartbeat - call this regularly from main thread
        /// </summary>
        public void Heartbeat()
        {
            _lastHeartbeat = DateTime.Now;
        }

        /// <summary>
        /// Register hashcat process for monitoring
        /// </summary>
        public void RegisterHashcatProcess(Process process)
        {
            if (process != null && !process.HasExited)
            {
                _hashcatProcessId = process.Id;
                Log($"Registered hashcat process: {process.Id}");
            }
        }

        /// <summary>
        /// Unregister hashcat process (when it exits normally)
        /// </summary>
        public void UnregisterHashcatProcess()
        {
            if (_hashcatProcessId.HasValue)
            {
                Log($"Unregistered hashcat process: {_hashcatProcessId}");
                _hashcatProcessId = null;
            }
        }

        /// <summary>
        /// Set current archive path for checkpoint saving
        /// </summary>
        public void SetCurrentArchive(string path)
        {
            _currentArchivePath = path;
        }

        /// <summary>
        /// Set checkpoint save callback
        /// </summary>
        public void SetCheckpointCallback(Action saveAction, Func<CheckpointData> getDataFunc)
        {
            _saveCheckpointAction = saveAction;
            _getCheckpointDataFunc = getDataFunc;
        }

        /// <summary>
        /// Main watchdog loop
        /// </summary>
        private void WatchdogLoop()
        {
            while (_isRunning)
            {
                try
                {
                    // Wait for check interval or stop signal
                    if (_stopEvent.WaitOne(_checkInterval))
                    {
                        break; // Stop signal received
                    }

                    // Check if main thread is responsive
                    var timeSinceHeartbeat = DateTime.Now - _lastHeartbeat;

                    if (timeSinceHeartbeat > _heartbeatTimeout)
                    {
                        Log($"WARNING: Main thread unresponsive for {timeSinceHeartbeat.TotalSeconds:F0} seconds");

                        // Try to save checkpoint
                        TryEmergencyCheckpointSave();

                        // If unresponsive for too long, kill hashcat
                        if (timeSinceHeartbeat > TimeSpan.FromMinutes(2))
                        {
                            Log("CRITICAL: Main thread unresponsive for 2+ minutes, killing hashcat");
                            KillHashcatProcess();
                        }
                    }

                    // Check if hashcat is still running but main process died
                    if (_hashcatProcessId.HasValue)
                    {
                        CheckHashcatOrphan();
                    }
                }
                catch (Exception ex)
                {
                    Log($"Watchdog error: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Check if hashcat has become orphaned
        /// </summary>
        private void CheckHashcatOrphan()
        {
            try
            {
                // Check if main process still exists
                try
                {
                    Process.GetProcessById(_mainProcessId);
                }
                catch (ArgumentException)
                {
                    // Main process died, kill hashcat
                    Log("Main process died, killing orphaned hashcat");
                    KillHashcatProcess();
                    return;
                }

                // Check if hashcat is still running
                if (_hashcatProcessId.HasValue)
                {
                    try
                    {
                        var hashcat = Process.GetProcessById(_hashcatProcessId.Value);
                        if (hashcat.HasExited)
                        {
                            _hashcatProcessId = null;
                        }
                    }
                    catch (ArgumentException)
                    {
                        _hashcatProcessId = null;
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"CheckHashcatOrphan error: {ex.Message}");
            }
        }

        /// <summary>
        /// Kill hashcat process
        /// </summary>
        public void KillHashcatProcess()
        {
            if (!_hashcatProcessId.HasValue) return;

            try
            {
                var process = Process.GetProcessById(_hashcatProcessId.Value);
                if (!process.HasExited)
                {
                    // Try graceful quit first (send 'q' key)
                    try
                    {
                        // Can't send keys from background thread, just kill it
                        process.Kill();
                        process.WaitForExit(5000);
                        Log($"Killed hashcat process: {_hashcatProcessId}");
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"KillHashcatProcess error: {ex.Message}");
            }
            finally
            {
                _hashcatProcessId = null;
            }
        }

        /// <summary>
        /// Try to save checkpoint in emergency situation
        /// NOTE: Cannot call UI functions from background thread, so just log the warning
        /// Checkpoint is saved periodically from the UI thread heartbeat timer instead
        /// </summary>
        private void TryEmergencyCheckpointSave()
        {
            try
            {
                // Do NOT call _getCheckpointDataFunc here - it accesses UI elements
                // which would cause cross-thread exception and freeze the app
                Log("WARNING: Main thread unresponsive - checkpoint should be saved from UI thread");
            }
            catch (Exception ex)
            {
                Log($"Emergency checkpoint warning failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Clean up orphaned hashcat processes from previous crash
        /// </summary>
        public void CleanupOrphanedHashcatProcesses()
        {
            try
            {
                var hashcatProcesses = Process.GetProcessesByName("hashcat");
                foreach (var process in hashcatProcesses)
                {
                    try
                    {
                        // Check if this hashcat was started by our previous instance
                        // by checking if it's running longer than expected startup time
                        if ((DateTime.Now - process.StartTime).TotalMinutes > 1)
                        {
                            // Check if parent process exists
                            bool hasParent = false;
                            try
                            {
                                // This is a simplified check - in production you'd check parent PID
                                hasParent = process.MainWindowHandle != IntPtr.Zero;
                            }
                            catch { }

                            if (!hasParent)
                            {
                                Log($"Killing orphaned hashcat process: {process.Id} (started at {process.StartTime})");
                                process.Kill();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error checking hashcat process {process.Id}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"CleanupOrphanedHashcatProcesses error: {ex.Message}");
            }
        }

        /// <summary>
        /// Write to log file
        /// </summary>
        private void Log(string message)
        {
            try
            {
                var logDir = Path.GetDirectoryName(LogPath);
                if (!Directory.Exists(logDir))
                    Directory.CreateDirectory(logDir);

                var logLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(LogPath, logLine + Environment.NewLine);

                // Also write to debug output
                Debug.WriteLine($"[Watchdog] {message}");
            }
            catch { }
        }

        /// <summary>
        /// Get watchdog status
        /// </summary>
        public WatchdogStatus GetStatus()
        {
            return new WatchdogStatus
            {
                IsRunning = _isRunning,
                LastHeartbeat = _lastHeartbeat,
                TimeSinceHeartbeat = DateTime.Now - _lastHeartbeat,
                HashcatProcessId = _hashcatProcessId,
                IsHashcatRunning = _hashcatProcessId.HasValue && IsProcessRunning(_hashcatProcessId.Value)
            };
        }

        private bool IsProcessRunning(int pid)
        {
            try
            {
                var process = Process.GetProcessById(pid);
                return !process.HasExited;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            Stop();
            _stopEvent?.Dispose();
        }
    }

    /// <summary>
    /// Watchdog status information
    /// </summary>
    public class WatchdogStatus
    {
        public bool IsRunning { get; set; }
        public DateTime LastHeartbeat { get; set; }
        public TimeSpan TimeSinceHeartbeat { get; set; }
        public int? HashcatProcessId { get; set; }
        public bool IsHashcatRunning { get; set; }
    }
}
