using System;
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
            using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "results.txt")))
            {
                outputFile.WriteLine("Results of Recon: ");
            }
            Console.WriteLine("Conduct local system recon? Enter 'y' or 'n' or 'exit':");
            string machineInfo = Console.ReadLine();

            //Determine if user wants to do a local recon scan
            while(machineInfo != "y" && machineInfo != "n")
            {
                Console.WriteLine("Invalid selection. Would you like to conduct local system recon? Enter 'y' or 'n' or 'exit': ");
                machineInfo = Console.ReadLine();
            }

            //Run local recon if user selects yes
            if (machineInfo == "y")
            {
                localMachine();
            }
            else if (machineInfo == "exit")
            {
                Environment.Exit(0);
            }

            //See if user wants to do a network scan
            var networkScan = networkChoice();
            //If they select yes, get type
            if (networkScan == "n")
            {
                Environment.Exit(0);
            }

            //Continue with scan if not exited
            //Get type of scan
            var scanType = userSelection();

            //Get Default gateway
            string localIp = Convert.ToString(GetDefaultGateway());

            //Get choice whether user wants to use default gateway or different subnet, then valid
            var ipChoice = userIpChoice(localIp);

            //Get port type selection
            var portChoice = portSelection();

            //Get stripped IP from ip Choice
            var strippedIp = stripIP(ipChoice);

            //Get user info if WMI
            while (scanning(scanType, portChoice, strippedIp, ipChoice) == true)
            {
                if (scanning(scanType, portChoice, strippedIp, ipChoice) == false)
                {
                    Console.WriteLine("Scanning Finished. Exiting.");
                    break;
                }
            }

        }


        //Function to start scanning
        public static bool scanning(string scanType, string portChoice, string strippedIp, string ipChoice)
        {
            bool scanning = true;
            if (scanType == "1")
            {
                string type = "wmic";
                //get and set user
                Console.WriteLine("Enter user name:");
                string wmiUsername = Console.ReadLine();
                //Password
                Console.WriteLine("Enter password:");
                string wmiPassword = Console.ReadLine();
                //Get computer domain
                Console.WriteLine("Enter network domain:");
                string domainURL = Console.ReadLine();
                //Network plus WMI scan starts
                Console.WriteLine("Scanning started");
                scanFunction(portChoice, strippedIp, ipChoice, type, wmiUsername, wmiPassword, domainURL, scanning);
            }
            else if (scanType == "2")
            {
                string type = "network";
                scanFunction(portChoice, strippedIp, ipChoice, type, "", "", "", scanning);
            }
            return scanning;
        }

        //Function for port selection
        public static string portSelection()
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
        public static string userIpChoice(string defaultGateway)
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
                validateIP(subnet);
            }
            else if (whichNetwork == "n")
            {
                Console.WriteLine("Please enter a subnet to scan. For example, '192.168.0.1':");
                subnet = Console.ReadLine();
                if (validateIP(subnet) == false)
                {
                    Console.WriteLine("Invalid IP. Please enter a subnet to scan. For example, '192.168.0.1':");
                }
            }
            return subnet;
        }

        //Function for checking if user wants to run network scan
        public static string networkChoice()
        {
            Console.WriteLine("Would you like to complete a network scan? Enter 'y' or 'n':");
            string networkChoice = Console.ReadLine();

            while (networkChoice != "y" && networkChoice != "n")
            {
                Console.WriteLine("Invalid selection. Would you like to complete a network scan? Enter 'y' or 'n': ");
                networkChoice = Console.ReadLine();
            }
            return networkChoice;
             
        }

        //Function for what type of scan
        public static string userSelection()
        {
            Console.WriteLine("Please select scan type: type '1' for WMI + Network (REQUIRES Domain User Credentials) or '2' for Network ONLY:");
            string scanType = Console.ReadLine();

            while (scanType != "1" && scanType != "2")
            {
                scanType = Console.ReadLine();
            }
            return scanType;
        }


        public static void localMachine()
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
                for (int i = 0; i< matches.Count; i++)
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

        //Get Subnet
        public static string getSubnet()
        {
            //Get IP range
            Console.WriteLine("Please enter the subnet to be scanned, for example '192.168.0.1' :");
            string subnet = Console.ReadLine();
            return subnet;
        }

        //Validate IP
        public static string stripIP(string subnet)
        {
            //Split IP into array
            string[] splitAddress = subnet.Split('.');

            //Joins IP back together without the 4th octet
            string strippedIP = string.Join(".", splitAddress, 0, 3) + ".";
            return strippedIP;
        }

        public static void wmiFunction(string hostname, string wmiUsername, string wmiPassword, string domainURL, bool scanning)
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
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
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
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        File.AppendAllText(docPath + "\\results.txt", userResults + Environment.NewLine);
                        Console.WriteLine(userResults);
                        Console.WriteLine(user);
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    //Console.WriteLine(e);
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
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        File.AppendAllText(docPath + "\\results.txt", logonResults + Environment.NewLine);
                        Console.WriteLine(logonResults);
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception)
                {
                    //Console.WriteLine(e);
                }


            }
            catch (Exception)
            {
                //Console.WriteLine(e);
            }

        }



        //Function for selected IP scan
        public static bool selectedScan(string hostname, int port, string type, string wmiUsername, string wmiPassword, string domainURL, bool scanning)
        {
            //WMI
            if (type == "wmic")
            {
                string results = "";
                for (int i = 1; i < 256; i++)
                {
                    try
                    {
                        var client = new TcpClient();
                        {
                            if (!client.ConnectAsync(hostname + Convert.ToString(i), port).Wait(1000))
                            {
                                // connection failure
                                Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " failed.");
                            }
                            else
                            {
                                Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.");
                                results = "Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.";
                                string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                                File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                                if (results.Contains("succeeded") && Convert.ToString(port) == "135")
                                {
                                    Console.WriteLine("Port 135 confirmed");
                                    wmiFunction(hostname + Convert.ToString(i), wmiUsername, wmiPassword, domainURL, scanning);

                                }
                            }
                        }
                    }
                    catch (Exception)
                    {

                    }

                }

            }
            //Network only
            else
            {
                string results = "";
                for (int i = 1; i < 256; i++)
                {
                    try
                    {
                        var client = new TcpClient();
                        {
                            if (!client.ConnectAsync(hostname + Convert.ToString(i), port).Wait(1000))
                            {
                                // connection failure
                                Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " failed.");
                            }
                            else
                            {
                                Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.");
                                results = "Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.";
                                string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                                File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                            }
                        }
                    }
                    catch (Exception)
                    {
                    }
                }

            }
            scanning = false;
            return scanning;
        }

        //Full port scan
        public static bool wideScan(string hostname, int port, string type, string wmiUsername, string wmiPassword, string domainURL, bool scanning)
        {

            if (type == "wmic")
            {
                string results = "";
                try
                {
                    var client = new TcpClient();
                    {
                        if (!client.ConnectAsync(hostname, +port).Wait(1000))
                        {
                            // connection failure
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.");
                            results = "Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);
                            if (results.Contains("succeeded") && Convert.ToString(port) == "135")
                            {
                                Console.WriteLine("Port 135 confirmed");
                                wmiFunction(hostname, wmiUsername, wmiPassword, domainURL, scanning);
                                wmiTargets(hostname);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    //Console.WriteLine(e);
                }
                
            }
            else if(type == "network")
            {
                string results = "";
                try
                {
                    var client = new TcpClient();
                    {
                        if (!client.ConnectAsync(hostname, +port).Wait(1000))
                        {
                            // connection failure
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.");
                            results = "Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine + Environment.NewLine);

                        }
                    }
                }
                catch (Exception)
                {
                    //Console.WriteLine(e);
                }

            }
            scanning = false;
            return scanning;

        }

        //Checks if IP address is valid
        public static bool validateIP(string ipString)
        {
            if (ipString.Count(c => c == '.') != 3) return false;
            IPAddress address;
            return IPAddress.TryParse(ipString, out address);
        }


        //Multithread IP Split 
        public static bool multiIP(string ip, int startIp, int stopIp, int portStart, int portStop, string type, string wmiUsername, string wmiPassword, string domainURL, bool scanning)
        {
            for (int i = startIp; i < stopIp; i++)
            {
                for (int j = portStart; j < portStop; j++)
                {
                    wideScan(ip + Convert.ToString(i), j, type, wmiUsername, wmiPassword, domainURL, scanning);
                    scanning = false;
                    
                }
            }
            return scanning;
        }

        //User scan selection
        public static void scanSelection(string choice)
        {
            while (choice != "1" && choice != "2" && choice != "3" && choice != "exit")
            {
                Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, and 3 for selected port scan or 'exit': ");
                choice = Console.ReadLine();
            }
        }

        //Scan functions
        public static void scanFunction(string choice, string strippedIP, string subnet, string type, string wmiUsername, string wmiPassword, string domainURL, bool scanning)
        {

            //Path for document saving
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (choice == "1")
            {

                Console.WriteLine("Caution: Full scanning may fire alerts on network intrusion detection systems, type 'yes' to proceed or 'back' to select a different option: ");
                string choice2 = Console.ReadLine();

                while (choice2 != "yes" && choice2 != "back")
                {
                    choice2 = Console.ReadLine();
                }

                if (choice2 == "yes")
                {
                    Console.WriteLine("Starting full scan, please wait until message complete...");
                    try
                    {

                        //Spool up threads
                        Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 16385, type, wmiUsername, wmiPassword, domainURL, scanning));
                        thread.Start();

                        Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 16384, 32769, type, wmiUsername, wmiPassword, domainURL, scanning));
                        thread2.Start();

                        Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 32768, 49153, type, wmiUsername, wmiPassword, domainURL, scanning));
                        thread3.Start();

                        Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 49152, 65536, type, wmiUsername, wmiPassword, domainURL, scanning));
                        thread4.Start();

                    }
                    catch
                    {

                    }
                }
                else if (choice2 == "back")
                {
                    choice = "0";
                    scanSelection(choice);
                }



            }
            //Run scan only on well-know ports
            else if (choice == "2")
            {
                Console.WriteLine("Starting well-known scan, please wait for scan complete message...");
                try
                {
                    Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 257, type, wmiUsername, wmiPassword, domainURL, scanning));
                    thread.Start();

                    Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 256, 513, type, wmiUsername, wmiPassword, domainURL, scanning));
                    thread2.Start();

                    Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 512, 769, type, wmiUsername, wmiPassword, domainURL, scanning));
                    thread3.Start();

                    Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 768, 1024, type, wmiUsername, wmiPassword, domainURL, scanning));
                    thread4.Start();
                }
                catch
                {

                }

            }
            //Run scan on ports chosen by user
            else if (choice == "3")
            {
                //Get port number from user
                Console.WriteLine("Please enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                if (ports != "")
                {
                    if (ports.Contains(" "))
                    {
                        //Replace any spaces
                        ports.Replace(" ", "");
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
                            Thread thread = new Thread(() => selectedScan(strippedIP, Convert.ToInt32(portNumber), type, wmiUsername, wmiPassword, domainURL, scanning));
                            thread.Start();
                        }
                    }
                    else
                    {
                        Console.WriteLine("Starting selected scan on port(s): " + Convert.ToString(ports));
                        List<int> portList = new List<int>();
                        string[] fullList = ports.Split(',');
                        foreach (var portNumber in fullList)
                        {
                            portList.Add(Convert.ToInt32(portNumber));
                        }
                        //Run scan
                        foreach (var portNumber in fullList)
                        {
                            Thread thread = new Thread(() => selectedScan(strippedIP, Convert.ToInt32(portNumber), type, wmiUsername, wmiPassword, domainURL, scanning));
                            thread.Start();
                        }
                    }

                }
            }
        }
        public static List<string> wmiTargets(string wmiTarget)
        {
            List<string> wmiRange = new List<string>();
            wmiRange.Add(wmiTarget);

            return wmiRange;
        }

        //For attacking found WMI targets later
        public static void attackWMI()
        {
            Console.WriteLine("Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
            string targetWmi = Console.ReadLine();

            while (targetWmi != "y" && targetWmi != "n" && targetWmi != "exit")
            {
                Console.WriteLine("Invalid command. Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
                targetWmi = Console.ReadLine();
            }
            if (targetWmi == "y")
            {
                foreach (string target in wmiTargets(""))
                {
                    Console.WriteLine(target);
                }
            }
        }
    }
}
