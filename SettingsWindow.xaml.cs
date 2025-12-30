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
        public string SevenZ2JohnPath { get; private set; }
        public string PerlPath { get; private set; }
        public string Rar2JohnPath { get; private set; }
        public string DictionaryPath { get; private set; }
        public bool SettingsSaved { get; private set; }

        public SettingsWindow(string currentHashcatPath = null, bool autoDetect = true, string current7z2johnPath = null, string currentPerlPath = null, string currentDictionaryPath = null, string currentRar2johnPath = null)
        {
            InitializeComponent();

            txtHashcatPath.Text = currentHashcatPath ?? "";
            chkAutoDetectHashcat.IsChecked = autoDetect;
            txt7z2johnPath.Text = current7z2johnPath ?? "";
            txtPerlPath.Text = currentPerlPath ?? "";
            txtRar2johnPath.Text = currentRar2johnPath ?? "";
            txtDictionaryPath.Text = currentDictionaryPath ?? "";
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

        private void BtnBrowse7z2john_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select 7z2john Script",
                Filter = "Perl Script|7z2john.pl;*.pl|All Files|*.*",
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                txt7z2johnPath.Text = dialog.FileName;
            }
        }

        private void BtnBrowsePerl_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Perl Executable",
                Filter = "Perl Executable|perl.exe|All Files|*.*",
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                txtPerlPath.Text = dialog.FileName;
            }
        }

        private void BtnBrowseDictionary_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Dictionary/Wordlist File",
                Filter = "Text Files|*.txt|All Files|*.*",
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                txtDictionaryPath.Text = dialog.FileName;
            }
        }

        private void BtnBrowseRar2john_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select rar2john Executable",
                Filter = "Executable|rar2john.exe|All Files|*.*",
                CheckFileExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                txtRar2johnPath.Text = dialog.FileName;
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            HashcatPath = txtHashcatPath.Text;
            AutoDetectHashcat = chkAutoDetectHashcat.IsChecked == true;
            SevenZ2JohnPath = txt7z2johnPath.Text;
            PerlPath = txtPerlPath.Text;
            Rar2JohnPath = txtRar2johnPath.Text;
            DictionaryPath = txtDictionaryPath.Text;
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
