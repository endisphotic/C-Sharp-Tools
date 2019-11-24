using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using Neko.UserChoices;

namespace Neko.Discovery.PortScanning
{
    class Scanner
    {
        // Scan without WMI
        public static bool Scan(string strippedIP, string portChoice, string type, string Username, string Password, string domainURL, string nekoFolder)
        {
            // Full port scan
            if (portChoice == "1")
            {
                Console.WriteLine("Starting full port scan, this will take a while, please wait for scan finished message...");
                // Spool up multiple threads split by ports
                try
                {
                    Thread thread = new Thread(() => Ports(strippedIP, 1, 65, 1, 65536, type, Username, Password, domainURL, nekoFolder));
                    thread.Start();

                    Thread thread2 = new Thread(() => Ports(strippedIP, 64, 129, 1, 65536, type, Username, Password, domainURL, nekoFolder));
                    thread2.Start();

                    Thread thread3 = new Thread(() => Ports(strippedIP, 128, 193, 1, 65536, type, Username, Password, domainURL, nekoFolder));
                    thread3.Start();

                    Thread thread4 = new Thread(() => Ports(strippedIP, 192, 256, 1, 65536, type, Username, Password, domainURL, nekoFolder));
                    thread4.Start();

                    while (thread4.IsAlive == true)
                    {

                    }
                }
                catch
                {

                }
            }
            // Well-known scan
            else if (portChoice == "2")
            {
                Console.WriteLine("Starting well-known scan, this will take a while, please wait for scan finished message...");
                // Spool up multiple threads based on ports
                try
                {
                    Thread thread = new Thread(() => Ports(strippedIP, 1, 65, 1, 1025, type, Username, Password, domainURL, nekoFolder));
                    thread.Start();

                    Thread thread2 = new Thread(() => Ports(strippedIP, 64, 129, 1, 1025, type, Username, Password, domainURL, nekoFolder));
                    thread2.Start();

                    Thread thread3 = new Thread(() => Ports(strippedIP, 128, 193, 1, 1025, type, Username, Password, domainURL, nekoFolder));
                    thread3.Start();

                    Thread thread4 = new Thread(() => Ports(strippedIP, 192, 256, 1, 1025, type, Username, Password, domainURL, nekoFolder));
                    thread4.Start();

                    while (thread4.IsAlive == true)
                    {

                    }
                }
                catch
                {

                }
            }
            return false;
        }

        // Ports
        public static void Ports(string strippedIP, int startIp, int stopIp, int portStart, int portStop, string type, string Username, string Password, string domainURL, string nekoFolder)
        {
            // WMI Scan
            if (type == "1")
            {
                // Go through all IPs
                for (int i = startIp; i < stopIp; i++)
                {
                    // And loop through each port
                    for (int j = portStart; j < portStop; j++)
                    {
                        string results = "";
                        try
                        {
                            var client = new TcpClient();
                            {
                                if (!client.ConnectAsync(strippedIP + Convert.ToString(i), +j).Wait(1000))
                                {
                                    // connection failure
                                    Console.WriteLine("Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " failed.");
                                }
                                else
                                {
                                    Console.WriteLine("Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " succeeded.");
                                    results = "Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " succeeded.";
                                    // Write out results
                                    File.AppendAllText(nekoFolder + "\\Network IP Scan " + strippedIP + Convert.ToString(i) + ".txt", results + Environment.NewLine + Environment.NewLine);
                                    string wmiHost = "\\Network IP Scan " + strippedIP + Convert.ToString(i) + ".txt";
                                    if (results.Contains("succeeded") && (j) == 135)
                                    {
                                        Console.WriteLine("Port 135 confirmed");
                                        // Launch WMI recon info
                                        GatherInfoUsingWMI.Parameters(strippedIP + Convert.ToString(i), Username, Password, domainURL, nekoFolder, wmiHost);
                                        // Add to WMI list
                                        UserScanSelection.WMITargets.Add(strippedIP + Convert.ToString(i));

                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Console.WriteLine(e);
                        }
                    }
                }
            }
            // Network only
            else if (type == "2")
            {
                // Loop through IPs
                for (int i = startIp; i < stopIp; i++)
                {
                    // Loop through ports
                    for (int j = portStart; j < portStop; j++)
                    {
                        string results = "";
                        try
                        {
                            var client = new TcpClient();
                            {
                                if (!client.ConnectAsync(strippedIP + Convert.ToString(i), +j).Wait(1000))
                                {
                                    // connection failure
                                    Console.WriteLine("Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " failed.");
                                }
                                else
                                {
                                    Console.WriteLine("Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " succeeded.");
                                    results = "Connection to " + strippedIP + Convert.ToString(i) + " on port: " + Convert.ToString(j) + " succeeded.";
                                    // Write out results
                                    File.AppendAllText(nekoFolder + "\\Network IP Scan " + strippedIP + Convert.ToString(i) + ".txt", results + Environment.NewLine + Environment.NewLine);
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Console.WriteLine(e);
                        }
                    }
                }
            }
        }
    }
}
