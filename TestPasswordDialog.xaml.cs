using System.IO;
using System.Windows;
using System.Windows.Media;

namespace ZipCrackerUI
{
    public partial class TestPasswordDialog : Window
    {
        private readonly ZipCrackEngine _engine;
        private readonly string _zipPath;

        public TestPasswordDialog(ZipCrackEngine engine, string zipPath)
        {
            InitializeComponent();
            _engine = engine;
            _zipPath = zipPath;

            txtPassword.Focus();
        }

        private void BtnTest_Click(object sender, RoutedEventArgs e)
        {
            string password = txtPassword.Text;

            if (string.IsNullOrEmpty(password))
            {
                lblResult.Text = "Please enter a password to test.";
                lblResult.Foreground = new SolidColorBrush(Color.FromRgb(255, 170, 0));
                return;
            }

            lblResult.Text = "Testing password...";
            lblResult.Foreground = new SolidColorBrush(Color.FromRgb(136, 136, 136));
            btnTest.IsEnabled = false;

            // Test the password
            bool isValid = _engine.VerifyPassword(password);

            if (isValid)
            {
                lblResult.Text = $"✅ SUCCESS!\n\nPassword '{password}' is CORRECT!\n\nThe archive can be extracted with this password.";
                lblResult.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 136));

                // Copy to clipboard
                Clipboard.SetText(password);

                // Save to file
                try
                {
                    string dir = Path.GetDirectoryName(_zipPath);
                    if (!string.IsNullOrEmpty(dir))
                    {
                        File.WriteAllText(Path.Combine(dir, "FOUND_PASSWORD.txt"),
                            $"Password: {password}\nFile: {_zipPath}");
                    }
                }
                catch { }
            }
            else
            {
                lblResult.Text = $"❌ INCORRECT\n\nPassword '{password}' is not correct.\n\nTry another password.";
                lblResult.Foreground = new SolidColorBrush(Color.FromRgb(233, 69, 96));
            }

            btnTest.IsEnabled = true;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
