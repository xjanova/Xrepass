using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;

namespace ZipCrackerUI
{
    public partial class SettingsWindow : Window
    {
        public string HashcatPath { get; private set; }
        public bool AutoDetectHashcat { get; private set; }
        public bool SettingsSaved { get; private set; }

        public SettingsWindow(string currentHashcatPath = null, bool autoDetect = true)
        {
            InitializeComponent();

            txtHashcatPath.Text = currentHashcatPath ?? "";
            chkAutoDetectHashcat.IsChecked = autoDetect;
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                DragMove();
        }

        private void BtnBrowseHashcat_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Hashcat Executable",
                Filter = "Hashcat Executable|hashcat.exe|All Files|*.*",
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                txtHashcatPath.Text = dialog.FileName;
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            HashcatPath = txtHashcatPath.Text;
            AutoDetectHashcat = chkAutoDetectHashcat.IsChecked == true;
            SettingsSaved = true;
            DialogResult = true;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            SettingsSaved = false;
            DialogResult = false;
            Close();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            BtnCancel_Click(sender, e);
        }
    }
}
