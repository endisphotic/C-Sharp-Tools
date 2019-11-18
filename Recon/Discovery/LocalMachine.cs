using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace Neko
{
    class LocalMachineRecon
    {
        public static void LocalMachine(string nekoFolder)
        {
            //Net commands
            try
            {
                //New array for commands
                string[] netDomain = new string[5];
                netDomain[0] = "accounts";
                netDomain[1] = "group \"domain admins\" /domain";
                netDomain[2] = "localgroup administrators";
                netDomain[3] = "group \"domain controllers\" /domain";
                netDomain[4] = "start";

                //Get unique file to prevent overwriting
                string writePath = UniqueFileCheck.UniqueFile(nekoFolder + "\\Local Account Information.txt");

                //Start stream writer for writing results
                using (var writer = new StreamWriter(writePath, append: true))
                {
                    foreach (string argument in netDomain)
                    {
                        //Start new process
                        Process netProcess = new Process();
                        //Configure process
                        ProcessStartInfo netConfig = new ProcessStartInfo();
                        netConfig.WindowStyle = ProcessWindowStyle.Hidden;
                        netConfig.CreateNoWindow = true;
                        //Launch cmd
                        netConfig.FileName = "net.exe";
                        //Enable reading output
                        netConfig.RedirectStandardOutput = true;
                        netConfig.RedirectStandardError = true;
                        netConfig.UseShellExecute = false;
                        //Pass arguments
                        //netConfig.Arguments = netDomain;
                        netProcess.StartInfo = netConfig;
                        netConfig.Arguments = argument;
                        netProcess.Start();
                        string netDomainResult = netProcess.StandardOutput.ReadToEnd();
                        string netErr = netProcess.StandardError.ReadToEnd();
                        //Write results and clear buffer
                        writer.WriteLine(netDomainResult + netErr + Environment.NewLine);
                        writer.Flush();
                        Console.WriteLine(netDomainResult);
                    }
                }


            }
            catch (Exception)
            {
                Console.WriteLine("Command requires you are logged in with a domain account.");
            }
            //CMD commands
            try
            {
                //Array for commands
                string[] cmdArgs = new string[5];
                cmdArgs[0] = "/c arp -a";
                cmdArgs[1] = "/c route print";
                cmdArgs[2] = "/c netstat -ano | find /i \"listening\"";
                cmdArgs[3] = "/c ipconfig /all";
                cmdArgs[4] = "/c tasklist";


                //Get unique name
                //Get unique file to prevent overwriting
                string writePath = UniqueFileCheck.UniqueFile(nekoFolder + "\\Local Machine Network and Task Recon.txt");

                //Start stream writer for writing results
                using (var writer = new StreamWriter(writePath, append: true))
                {
                    foreach (string argument in cmdArgs)
                    {
                        //Start new process
                        Process cmdProcess = new Process();
                        //Configure process
                        ProcessStartInfo cmdConfig = new ProcessStartInfo();
                        cmdConfig.WindowStyle = ProcessWindowStyle.Hidden;
                        cmdConfig.CreateNoWindow = true;
                        //Launch cmd
                        cmdConfig.FileName = "cmd.exe";
                        //Enable reading output
                        cmdConfig.RedirectStandardOutput = true;
                        cmdConfig.RedirectStandardError = true;
                        cmdConfig.UseShellExecute = false;
                        //Pass arguments
                        //netConfig.Arguments = netDomain;
                        cmdProcess.StartInfo = cmdConfig;
                        cmdConfig.Arguments = argument;
                        cmdProcess.Start();
                        string cmdDomainResult = cmdProcess.StandardOutput.ReadToEnd();
                        string cmdErr = cmdProcess.StandardError.ReadToEnd();
                        //Append local machine info to results
                        writer.WriteLine(cmdDomainResult + cmdErr + Environment.NewLine);
                        writer.Flush();

                        Console.WriteLine(cmdDomainResult);
                    }
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            //Get service permissions
            try
            {
                //Command
                string scArg = "/c sc query";
                Process scProcess = new Process();
                //Configure process
                ProcessStartInfo scConfig = new ProcessStartInfo();
                scConfig.WindowStyle = ProcessWindowStyle.Hidden;
                scConfig.CreateNoWindow = true;
                //Launch cmd
                scConfig.FileName = "cmd.exe";
                //Enable reading output
                scConfig.RedirectStandardOutput = true;
                scConfig.RedirectStandardError = true;
                scConfig.UseShellExecute = false;
                //Pass arguments
                //netConfig.Arguments = netDomain;
                scProcess.StartInfo = scConfig;
                scConfig.Arguments = scArg;
                scProcess.Start();
                string scResult = scProcess.StandardOutput.ReadToEnd();
                string scErr = scProcess.StandardError.ReadToEnd();
                //Append local machine info to results
                File.AppendAllText(nekoFolder + "\\Local Machine Services.txt", scResult + scErr + Environment.NewLine);
                Console.WriteLine(scResult);

                //Regex matching pattern for SERVICE_NAME:
                string pattern = @"(?<=\SERVICE_NAME:\s)(\w+)";

                //Create list for matched values
                List<string> serviceList = new List<string>();

                //Match regex pattern
                MatchCollection matches = Regex.Matches(scResult, pattern);
                for (int i = 0; i < matches.Count; i++)
                {
                    //Console.WriteLine(matches[i].ToString());
                    //serviceList.Add(matches[i].ToString());
                    string services = matches[i].ToString();
                    Console.WriteLine(services);
                    File.AppendAllText(nekoFolder + "\\Local Machine Services.txt", services + Environment.NewLine);
                    string scSDSHOW = "/c sc sdshow " + services;
                    Process scSdProcess = new Process();
                    //Configure process
                    ProcessStartInfo scSdConfig = new ProcessStartInfo();
                    scSdConfig.WindowStyle = ProcessWindowStyle.Hidden;
                    scSdConfig.CreateNoWindow = true;
                    //Launch cmd
                    scSdConfig.FileName = "cmd.exe";
                    //Enable reading output
                    scSdConfig.RedirectStandardOutput = true;
                    scSdConfig.RedirectStandardError = true;
                    scSdConfig.UseShellExecute = false;
                    //Pass arguments
                    //netConfig.Arguments = netDomain;
                    scSdProcess.StartInfo = scSdConfig;
                    scSdConfig.Arguments = scSDSHOW;
                    scSdProcess.Start();
                    string scSD = scSdProcess.StandardOutput.ReadToEnd();
                    string scSdErr = scSdProcess.StandardError.ReadToEnd();
                    //Append local machine info to results
                    File.AppendAllText(nekoFolder + "\\Local Machine Services.txt", scSD + scSdErr + Environment.NewLine);
                    Console.WriteLine(scSD);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
