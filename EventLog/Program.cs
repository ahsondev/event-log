using System;
using System.Windows.Forms;

namespace EventLog
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (sender, args) => Report(args.Exception);
            AppDomain.CurrentDomain.UnhandledException += (sender, args) => Report(args.ExceptionObject as Exception);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }

        static void Report(Exception exception)
        {
            var text = exception == null ? "Unknown error." : exception.ToString();
            MessageBox.Show(text, "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
