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

namespace Recon
{
	class Program
	{
		static void Main(string[] args)
		{

            Console.WriteLine("Welcome to the recon scanner.");
            Console.WriteLine("Please select scan type: type '1' for WMI + Network (REQUIRES Domain User Credentials) or '2' for Network ONLY:");
            string scanType = Console.ReadLine();

            while (scanType != "1" && scanType != "2")
            {
                scanType = Console.ReadLine();
            }

            if (scanType == "1")
            {

                Console.WriteLine("Please enter the subnet to be scanned, for example '192.168.0.1' :");
                string subnet = Console.ReadLine();
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
                networkScan(confirmIP(subnet), subnet, type, wmiUsername, wmiPassword, domainURL);
            }
            else if (scanType == "2")
            {
                Console.WriteLine("Please enter the subnet to be scanned, for example '192.168.0.1' :");
                string subnet = Console.ReadLine();
                string type = "";
                networkScan(confirmIP(subnet), subnet, type, "", "", "");
            }
            //Create document for scan results
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "results.txt")))
            {
                outputFile.WriteLine("Results of Recon: ");
            }


            Console.WriteLine("Scanning complete.");
        
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
        public static string confirmIP(string subnet)
        {
            
            string strippedIP = "";
            while (validateIP(subnet) == false)
            {
                Console.WriteLine("Invalid IP. Please enter the subnet to be scanned, for example '192.168.0.1' :");
                subnet = Console.ReadLine();
            }
            if (validateIP(subnet) == true)
            {
                //Split IP into array
                string[] splitAddress = subnet.Split('.');

                //Joins IP back together without the 4th octet
                strippedIP = string.Join(".", splitAddress, 0, 3) + ".";
            }
            return strippedIP;
        }

        public static void wmiFunction(string hostname, string wmiUsername, string wmiPassword, string domainURL)
        {
            try
            {
                Console.WriteLine("Establishing WMI");
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

                //AV Info
                ObjectQuery avQuery = new ObjectQuery("SELECT * FROM AntiVriusProduct");
                ManagementObjectSearcher avSearch = new ManagementObjectSearcher(scope, avQuery);

                //AV collection
                ManagementObjectCollection avCollection = avSearch.Get();

                try
                {

                    foreach (ManagementObject m in queryCollection)
                    {

                        string wmiScanResults = "Computer Name     : " + m["csname"] + "\r\n" +
                        "Operating System  : " + m["Caption"] + "\r\n" +
                        "Version           : " + m["Version"] + "\r\n" +
                        "Windows Directory : " + m["WindowsDirectory"] + "\r\n" +
                        "Manufacturer      : " + m["Manufacturer"];
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        File.AppendAllText(docPath + "\\results.txt", wmiScanResults + Environment.NewLine);
                        Console.WriteLine(wmiScanResults);
                    }

                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch(ManagementException e) when (e.Message.Contains("User credentials cannot be used for local connections"))
                {

                }

                try
                {
                    foreach (ManagementObject av in avCollection)
                    {
                        string avResults = "Antivirus Info: " + av["displayName"] + "\r\n" +
                            "Product State: " + av["productState"];
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        File.AppendAllText(docPath + "\\results.txt", avResults + Environment.NewLine);
                        Console.WriteLine(avResults);
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine(e);
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            
        }


        public static void networkScan(string strippedIP, string subnet, string type, string wmiUsername, string wmiPassword, string domainURL)
        {
            //Get user selection for type of scan
            Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, 3 for selected port scan, or 'exit':");
            string choice = Console.ReadLine();


            while (choice != "exit")
            {
                scanSelection(choice);
                if (choice == "1" || choice == "2" || choice == "3")
                {
                    scanFunction(choice, strippedIP, subnet, type, wmiUsername, wmiPassword, domainURL);

                }
                else if(choice == "exit")
                {
                    Environment.Exit(0);
                }
            }
        }



        public static void selectedScan(string hostname, int port, string type, string wmiUsername, string wmiPassword, string domainURL)
        {
            //string computerName = Console.ReadLine();
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
                            //Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.");
                            results = "Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine);
                            if (results.Contains("succeeded") && Convert.ToString(port) == "135")
                            {
                                Console.WriteLine("Port 135 confirmed");
                                wmiFunction(hostname + Convert.ToString(i), wmiUsername, wmiPassword, domainURL);
                                
                            }
                        }
                    }
                }
                catch (Exception)
                {
                }
            }

        }

        //Full port scan
        public static void wideScan(string hostname, int port, string type, string wmiUsername, string wmiPassword, string domainURL)
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
                            //Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.");
                            results = "Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine);
                            if (results.Contains("succeeded") && Convert.ToString(port) == "135")
                            {
                                Console.WriteLine("Port 135 confirmed");
                                wmiFunction(hostname, wmiUsername, wmiPassword, domainURL);
                                
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    //Console.WriteLine(e);
                }
            }
            else
            {
                string results = "";
                try
                {
                    var client = new TcpClient();
                    {
                        if (!client.ConnectAsync(hostname, +port).Wait(1000))
                        {
                            // connection failure
                            //Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.");
                            results = "Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine);
                            if (results.Contains("succeeded") && Convert.ToString(port) == "135")
                            {
                                Console.WriteLine("Port 135 confirmed");
                                wmiFunction(hostname, wmiUsername, wmiPassword, domainURL);
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

        //Checks if IP address is valid
        public static bool validateIP(string ipString)
        {
            if (ipString.Count(c => c == '.') != 3) return false;
            IPAddress address;
            return IPAddress.TryParse(ipString, out address);
        }


        //Multithread IP Split 
        public static void multiIP(string ip, int startIp, int stopIp, int portStart, int portStop, string type, string wmiUsername, string wmiPassword, string domainURL)
        {
            for (int i = startIp; i < stopIp; i++)
            {
                for (int j = portStart; j < portStop; j++)
                {
                    wideScan(ip + Convert.ToString(i), j, type, wmiUsername, wmiPassword, domainURL);
                }


            }
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
        public static void scanFunction(string choice, string strippedIP, string subnet, string type, string wmiUsername, string wmiPassword, string domainURL)
        {
            //Create stopwatch
            Stopwatch timer = new Stopwatch();
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
                        Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 16385, type, wmiUsername, wmiPassword, domainURL));
                        thread.Start();

                        Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 16384, 32769, type, wmiUsername, wmiPassword, domainURL));
                        thread2.Start();

                        Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 32768, 49153, type, wmiUsername, wmiPassword, domainURL));
                        thread3.Start();

                        Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 49152, 65536, type, wmiUsername, wmiPassword, domainURL));
                        thread4.Start();

                    }
                    catch
                    {

                    }
                    //finally Need to fix this later
                    //{
                    //    DateTime finish = DateTime.Now;
                    //    timer.Stop();
                    //    TimeSpan ts = timer.Elapsed;
                    //    string totalTime = "Scanning finished at: " + Convert.ToString(finish) + "\r\n" + "Total scan time: " + Convert.ToString(ts);
                    //    File.AppendAllText(docPath + "\\results.txt", totalTime + Environment.NewLine);
                    //}
                }
                else if (choice2 == "back")
                {
                    choice = "0";
                    scanSelection(choice);
                }

                Console.WriteLine("Full scan complete");


            }
            //Run scan only on well-know ports
            else if (choice == "2")
            {
                Console.WriteLine("Starting well-known scan, please wait for scan complete message...");
                try
                {
                    Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 257, type, wmiUsername, wmiPassword, domainURL));
                    thread.Start();

                    Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 256, 513, type, wmiUsername, wmiPassword, domainURL));
                    thread2.Start();

                    Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 512, 769, type, wmiUsername, wmiPassword, domainURL));
                    thread3.Start();

                    Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 768, 1024, type, wmiUsername, wmiPassword, domainURL));
                    thread4.Start();
                }
                catch
                {

                }
                Console.WriteLine("Well-known port scan complete");
            }
            //Run scan on ports chosen by user
            else if (choice == "3")
            {
                //Get port number from user
                Console.WriteLine("Please enter port numbers separated by commas: ");
                string ports = Console.ReadLine();
                //Need to fix double message
                while (ports == "")
                {
                    Console.WriteLine("Please enter port numbers separated by commas: ");
                    ports = Console.ReadLine();
                }
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
                        timer.Start();
                        foreach (var portNumber in fullList)
                        {
                            Thread thread = new Thread(() => selectedScan(strippedIP, Convert.ToInt32(portNumber), type, wmiUsername, wmiPassword, domainURL));
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
                        timer.Start();
                        foreach (var portNumber in fullList)
                        {
                            Thread thread = new Thread(() => selectedScan(strippedIP, Convert.ToInt32(portNumber), type, wmiUsername, wmiPassword, domainURL));
                            thread.Start();
                        }
                    }

                }
            }
        }
    }
}
