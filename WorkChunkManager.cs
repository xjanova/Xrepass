using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace ZipCrackerUI
{
    /// <summary>
    /// Manages work distribution across CPU and GPU threads with different chunk sizes.
    /// CPU threads get 1M chunks, GPU threads get 100M chunks.
    /// </summary>
    public class WorkChunkManager
    {
        private readonly object _lockObj = new object();
        private readonly long _totalWork;
        private long _nextChunkStart = 0;
        private readonly Dictionary<int, WorkChunk> _activeChunks = new Dictionary<int, WorkChunk>();
        private long _completedWork = 0;
        private long _cpuCompletedWork = 0;
        private long _gpuCompletedWork = 0;

        public const long CPU_CHUNK_SIZE = 1_000_000;  // 1M for CPU
        public const long GPU_CHUNK_SIZE = 100_000_000; // 100M for GPU

        public event EventHandler<ProgressEventArgs> ProgressUpdated;

        public WorkChunkManager(long totalWork)
        {
            _totalWork = totalWork;
        }

        /// <summary>
        /// Request a chunk of work for processing.
        /// </summary>
        /// <param name="workerType">Type of worker (CPU or GPU)</param>
        /// <param name="workerId">Unique identifier for this worker</param>
        /// <returns>WorkChunk to process, or null if no work remaining</returns>
        public WorkChunk? RequestChunk(WorkerType workerType, int workerId)
        {
            lock (_lockObj)
            {
                if (_nextChunkStart >= _totalWork)
                    return null;

                long chunkSize = workerType == WorkerType.CPU ? CPU_CHUNK_SIZE : GPU_CHUNK_SIZE;
                long start = _nextChunkStart;
                long end = Math.Min(start + chunkSize, _totalWork);

                var chunk = new WorkChunk
                {
                    ChunkId = _activeChunks.Count,
                    WorkerId = workerId,
                    WorkerType = workerType,
                    Start = start,
                    End = end,
                    Size = end - start,
                    RequestedAt = DateTime.Now
                };

                _activeChunks[chunk.ChunkId] = chunk;
                _nextChunkStart = end;

                return chunk;
            }
        }

        /// <summary>
        /// Report completion of a work chunk.
        /// </summary>
        /// <param name="chunkId">ID of completed chunk</param>
        /// <param name="actualProcessed">Number of items actually processed (may be less if password found)</param>
        public void ReportComplete(int chunkId, long actualProcessed)
        {
            lock (_lockObj)
            {
                if (!_activeChunks.TryGetValue(chunkId, out var chunk))
                    return;

                chunk.CompletedAt = DateTime.Now;
                chunk.ActualProcessed = actualProcessed;

                _completedWork += actualProcessed;

                if (chunk.WorkerType == WorkerType.CPU)
                    _cpuCompletedWork += actualProcessed;
                else
                    _gpuCompletedWork += actualProcessed;

                _activeChunks.Remove(chunkId);

                // Raise progress event
                ProgressUpdated?.Invoke(this, new ProgressEventArgs
                {
                    TotalWork = _totalWork,
                    CompletedWork = _completedWork,
                    CpuCompletedWork = _cpuCompletedWork,
                    GpuCompletedWork = _gpuCompletedWork,
                    ActiveChunks = _activeChunks.Count,
                    OverallProgress = (double)_completedWork / _totalWork * 100.0,
                    CpuProgress = (double)_cpuCompletedWork / _totalWork * 100.0,
                    GpuProgress = (double)_gpuCompletedWork / _totalWork * 100.0
                });
            }
        }

        /// <summary>
        /// Get current progress statistics.
        /// </summary>
        public ProgressStats GetProgress()
        {
            lock (_lockObj)
            {
                return new ProgressStats
                {
                    TotalWork = _totalWork,
                    CompletedWork = _completedWork,
                    CpuCompletedWork = _cpuCompletedWork,
                    GpuCompletedWork = _gpuCompletedWork,
                    RemainingWork = _totalWork - _completedWork,
                    ActiveChunks = _activeChunks.Count,
                    OverallProgress = (double)_completedWork / _totalWork * 100.0,
                    CpuProgress = (double)_cpuCompletedWork / _totalWork * 100.0,
                    GpuProgress = (double)_gpuCompletedWork / _totalWork * 100.0
                };
            }
        }

        /// <summary>
        /// Reset the work manager to start fresh.
        /// </summary>
        public void Reset()
        {
            lock (_lockObj)
            {
                _nextChunkStart = 0;
                _completedWork = 0;
                _cpuCompletedWork = 0;
                _gpuCompletedWork = 0;
                _activeChunks.Clear();
            }
        }

        /// <summary>
        /// Get list of currently active chunks.
        /// </summary>
        public List<WorkChunk> GetActiveChunks()
        {
            lock (_lockObj)
            {
                return _activeChunks.Values.ToList();
            }
        }
    }

    public enum WorkerType
    {
        CPU,
        GPU
    }

    public class WorkChunk
    {
        public int ChunkId { get; set; }
        public int WorkerId { get; set; }
        public WorkerType WorkerType { get; set; }
        public long Start { get; set; }
        public long End { get; set; }
        public long Size { get; set; }
        public long ActualProcessed { get; set; }
        public DateTime RequestedAt { get; set; }
        public DateTime? CompletedAt { get; set; }

        public TimeSpan? ProcessingTime => CompletedAt.HasValue
            ? CompletedAt.Value - RequestedAt
            : (TimeSpan?)null;
    }

    public class ProgressStats
    {
        public long TotalWork { get; set; }
        public long CompletedWork { get; set; }
        public long CpuCompletedWork { get; set; }
        public long GpuCompletedWork { get; set; }
        public long RemainingWork { get; set; }
        public int ActiveChunks { get; set; }
        public double OverallProgress { get; set; }
        public double CpuProgress { get; set; }
        public double GpuProgress { get; set; }
    }

    public class ProgressEventArgs : EventArgs
    {
        public long TotalWork { get; set; }
        public long CompletedWork { get; set; }
        public long CpuCompletedWork { get; set; }
        public long GpuCompletedWork { get; set; }
        public int ActiveChunks { get; set; }
        public double OverallProgress { get; set; }
        public double CpuProgress { get; set; }
        public double GpuProgress { get; set; }
    }
}
