using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.IO;

namespace Neko.Discovery.PortScanning
{
    class SelectedPorts
    {
        // Selected port scan method
        public static bool SelectedPortScan(string strippedIp, string scanType, string Username, string Password, string domainURL, string nekoFolder)
        {
            if (scanType == "1")
            {
                string results = "";
                // Get port numbers from user
                Console.WriteLine("\r\nPlease enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                if (ports != "")
                {
                    // Remove any spaces
                    if (ports.Contains(" "))
                    {
                        ports.Replace(" ", "");
                    }
                    Console.WriteLine("\r\nStarting selected scan on port(s): " + Convert.ToString(ports) + Environment.NewLine, Console.ForegroundColor = ConsoleColor.Red);
                    Console.ResetColor();
                    // Add ports to list
                    List<int> portList = new List<int>();
                    // Split out data by comma values
                    string[] fullList = ports.Split(',');
                    // Iteratively add to list
                    foreach (var portNumber in fullList)
                    {
                        portList.Add(Convert.ToInt32(portNumber));
                    }
                    // Run scan
                    foreach (var portNumber in fullList)
                    {
                        // Go through all 255 IPs of last octet
                        for (int i = 1; i < 256; i++)
                        {
                            try
                            {
                                var client = new TcpClient();
                                {
                                    if (!client.ConnectAsync(strippedIp + Convert.ToString(i), Convert.ToInt32(portNumber)).Wait(1000))
                                    {
                                        // connection failure
                                        Console.WriteLine("Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " failed.");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " succeeded.");
                                        results = "Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " succeeded.";
                                        // Append results to text file
                                        File.AppendAllText(nekoFolder + "\\Network IP Scan " + strippedIp + Convert.ToString(i) + ".txt", results + Environment.NewLine + Environment.NewLine);
                                        string wmiHost = "\\Network IP Scan " + strippedIp + Convert.ToString(i) + ".txt";
                                        if (results.Contains("succeeded") && Convert.ToInt32(portNumber) == 135)
                                        {
                                            Console.WriteLine("Port 135 confirmed", Console.ForegroundColor = ConsoleColor.DarkRed);
                                            Console.ResetColor();
                                            // Launch WMI recon
                                            GatherInfoUsingWMI.Parameters(strippedIp + Convert.ToString(i), Username, Password, domainURL, nekoFolder, wmiHost);
                                            // Add host to WMI list
                                            UserChoices.UserScanSelection.WMITargets.Add(strippedIp + Convert.ToString(i));
                                        }
                                    }
                                }
                            }
                            catch (Exception)
                            {

                            }
                        }
                    }
                }
            }
            else if (scanType == "2")
            {
                string results = "";
                // Get port number from user
                Console.WriteLine("\r\nPlease enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                if (ports != "")
                {
                    // Remove spaces
                    if (ports.Contains(" "))
                    {
                        ports.Replace(" ", "");
                    }
                    Console.WriteLine("\r\nStarting selected scan on port(s): " + Convert.ToString(ports));
                    // Add ports to list array
                    string[] fullList = ports.Split(',');

                    // Run scan
                    foreach (var portNumber in fullList)
                    {
                        // Go through each IP
                        for (int i = 1; i < 256; i++)
                        {
                            try
                            {
                                var client = new TcpClient();
                                {
                                    if (!client.ConnectAsync(strippedIp + Convert.ToString(i), Convert.ToInt32(portNumber)).Wait(1000))
                                    {
                                        // connection failure
                                        Console.WriteLine("Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " failed.");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " succeeded.");
                                        results = "Connection to " + strippedIp + Convert.ToString(i) + " on port: " + Convert.ToInt32(portNumber) + " succeeded.";
                                        // Append results to text document
                                        File.AppendAllText(nekoFolder + "\\Network IP Scan " + strippedIp + Convert.ToString(i) + ".txt", results + Environment.NewLine + Environment.NewLine);
                                    }
                                }
                            }
                            catch (Exception)
                            {

                            }
                        }
                    }
                }
            }
            return false;
        }
    }
}
