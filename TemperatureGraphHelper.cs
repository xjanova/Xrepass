using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace ZipCrackerUI
{
    /// <summary>
    /// Helper class for drawing temperature and usage graphs on Canvas.
    /// </summary>
    public class TemperatureGraphHelper
    {
        private readonly Canvas _canvas;
        private readonly int _maxDataPoints = 60; // 60 points for history
        private readonly List<double> _cpuTempHistory = new List<double>();
        private readonly List<double> _gpuTempHistory = new List<double>();
        private readonly List<double> _cpuUsageHistory = new List<double>();
        private readonly List<double> _gpuUsageHistory = new List<double>();

        public TemperatureGraphHelper(Canvas canvas)
        {
            _canvas = canvas ?? throw new ArgumentNullException(nameof(canvas));
        }

        /// <summary>
        /// Add new data point and redraw graph.
        /// </summary>
        public void AddDataPoint(double cpuTemp, double gpuTemp, double cpuUsage, double gpuUsage)
        {
            // Add to history
            _cpuTempHistory.Add(cpuTemp);
            _gpuTempHistory.Add(gpuTemp);
            _cpuUsageHistory.Add(cpuUsage);
            _gpuUsageHistory.Add(gpuUsage);

            // Keep only last N points
            if (_cpuTempHistory.Count > _maxDataPoints)
            {
                _cpuTempHistory.RemoveAt(0);
                _gpuTempHistory.RemoveAt(0);
                _cpuUsageHistory.RemoveAt(0);
                _gpuUsageHistory.RemoveAt(0);
            }

            // Redraw
            DrawGraph();
        }

        /// <summary>
        /// Clear all data and canvas.
        /// </summary>
        public void Clear()
        {
            _cpuTempHistory.Clear();
            _gpuTempHistory.Clear();
            _cpuUsageHistory.Clear();
            _gpuUsageHistory.Clear();
            _canvas.Children.Clear();
        }

        /// <summary>
        /// Draw the temperature and usage graphs.
        /// </summary>
        private void DrawGraph()
        {
            if (_canvas.ActualWidth <= 0 || _canvas.ActualHeight <= 0)
                return;

            _canvas.Children.Clear();

            double width = _canvas.ActualWidth;
            double height = _canvas.ActualHeight;

            // Draw grid lines
            DrawGridLines(width, height);

            // Draw graphs
            if (_cpuTempHistory.Count > 1)
            {
                DrawLine(_cpuTempHistory, width, height, Color.FromRgb(0, 255, 136), 100); // CPU temp (max 100°C)
                DrawLine(_gpuTempHistory, width, height, Color.FromRgb(255, 107, 53), 100); // GPU temp (max 100°C)
                DrawLine(_cpuUsageHistory, width, height, Color.FromArgb(128, 0, 255, 136), 100); // CPU usage (max 100%)
                DrawLine(_gpuUsageHistory, width, height, Color.FromArgb(128, 255, 107, 53), 100); // GPU usage (max 100%)
            }
        }

        /// <summary>
        /// Draw grid lines on canvas.
        /// </summary>
        private void DrawGridLines(double width, double height)
        {
            var gridBrush = new SolidColorBrush(Color.FromArgb(32, 255, 255, 255));

            // Horizontal lines (every 25%)
            for (int i = 1; i < 4; i++)
            {
                double y = height * i / 4.0;
                var line = new Line
                {
                    X1 = 0,
                    Y1 = y,
                    X2 = width,
                    Y2 = y,
                    Stroke = gridBrush,
                    StrokeThickness = 1,
                    StrokeDashArray = new DoubleCollection { 2, 2 }
                };
                _canvas.Children.Add(line);
            }

            // Vertical lines (every 20%)
            for (int i = 1; i < 5; i++)
            {
                double x = width * i / 5.0;
                var line = new Line
                {
                    X1 = x,
                    Y1 = 0,
                    X2 = x,
                    Y2 = height,
                    Stroke = gridBrush,
                    StrokeThickness = 1,
                    StrokeDashArray = new DoubleCollection { 2, 2 }
                };
                _canvas.Children.Add(line);
            }
        }

        /// <summary>
        /// Draw a line graph for the given data.
        /// </summary>
        private void DrawLine(List<double> data, double width, double height, Color color, double maxValue)
        {
            if (data.Count < 2)
                return;

            var points = new PointCollection();
            double xStep = width / (_maxDataPoints - 1);

            for (int i = 0; i < data.Count; i++)
            {
                double x = i * xStep;
                double y = height - (data[i] / maxValue * height);
                y = Math.Max(0, Math.Min(height, y)); // Clamp to canvas bounds
                points.Add(new Point(x, y));
            }

            // Create polyline
            var polyline = new Polyline
            {
                Points = points,
                Stroke = new SolidColorBrush(color),
                StrokeThickness = 2,
                StrokeLineJoin = PenLineJoin.Round
            };

            _canvas.Children.Add(polyline);

            // Add glow effect
            polyline.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = color,
                BlurRadius = 8,
                ShadowDepth = 0,
                Opacity = 0.6
            };
        }
    }
}
