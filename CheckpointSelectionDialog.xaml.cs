using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace ZipCrackerUI
{
    public partial class CheckpointSelectionDialog : Window
    {
        public CheckpointInfo SelectedCheckpoint { get; private set; }

        public CheckpointSelectionDialog(List<CheckpointInfo> checkpoints)
        {
            InitializeComponent();

            lstCheckpoints.ItemsSource = checkpoints;
            lstCheckpoints.SelectionChanged += LstCheckpoints_SelectionChanged;

            // Auto-select first item if available
            if (checkpoints.Count > 0)
            {
                lstCheckpoints.SelectedIndex = 0;
            }
        }

        private void LstCheckpoints_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            btnOk.IsEnabled = lstCheckpoints.SelectedItem != null;
        }

        private void LstCheckpoints_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (lstCheckpoints.SelectedItem != null)
            {
                BtnOk_Click(sender, null);
            }
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e)
        {
            SelectedCheckpoint = lstCheckpoints.SelectedItem as CheckpointInfo;
            DialogResult = true;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }

    // TimeSpan converter for XAML binding
    public class TimeSpanConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is double seconds)
            {
                var ts = TimeSpan.FromSeconds(seconds);
                return ts.ToString(@"hh\:mm\:ss");
            }
            return "00:00:00";
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
