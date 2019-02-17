using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Net;

namespace Recon
{
	class Program
	{
		static void Main(string[] args)
		{

            //Get IP range
			Console.WriteLine("Please enter the subnet to be scanned, for example '192.168.0.1' :");
			string subnet = Console.ReadLine();
            while(validateIP(subnet) == false)
            {
                Console.WriteLine("Invalid IP. Please enter the subnet to be scanned, for example '192.168.0.1' :");
                subnet = Console.ReadLine();
            }
            if(validateIP(subnet) == true)
            {
                //Split IP into array
                string [] splitAddress = subnet.Split('.');

                //Joins IP back together without the 4th octet
                string strippedIP = string.Join(".", splitAddress, 0, 3) + ".";
                
                //Create document for scan results
                string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "results.txt")))
                {
                    outputFile.WriteLine("Results of Recon: ");
                }

                //Get user selection for type of scan
                Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, and 3 for selected port scan: ");
                string choice = Console.ReadLine();


                scanSelection(choice);
                if(choice == "1" || choice == "2" || choice == "3")
                {
                    scanFunction(choice, strippedIP, subnet);
                }               

            }
		}


        public static void selectedScan(string hostname, int port)
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
                            Console.WriteLine("Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " failed.");
                        }
                        else
                        {
                            Console.WriteLine("Connection to " + hostname + " on port: " + port + " succeeded.");
                            results = "Connection to " + hostname + Convert.ToString(i) + " on port: " + port + " succeeded.";
                            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                            File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine);
                        }
                    }
                }
                catch (Exception)
                {
                }
            }

        }

        //Full port scan
        public static void wideScan(string hostname, int port)
        {


            //string computerName = Console.ReadLine();
            string results = "";
            try
            {
                var client = new TcpClient();
                {
                    if (!client.ConnectAsync(hostname, + port).Wait(1000))
                    {
                        // connection failure
                        Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " failed.");
                    }
                    else
                    {
                        Console.WriteLine("Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.");
                        results = "Connection to " + hostname + " on port: " + Convert.ToString(port) + " succeeded.";
                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        File.AppendAllText(docPath + "\\results.txt", results + Environment.NewLine);
                    }
                }
            }
            catch (Exception)
            {
                //Console.WriteLine(e);
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
        public static void multiIP(string ip, int startIp, int stopIp, int portStart, int portStop)
        {
            for (int i = startIp; i < stopIp; i++)
            {
                for (int j = portStart; j < portStop; j++)
                {
                    wideScan(ip + Convert.ToString(i), j);
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

        //Test

        //Scan functions
        public static void scanFunction(string choice, string strippedIP, string subnet)
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
                    Console.WriteLine("Starting full scan: ");
                    try
                    {

                        //Spool up threads
                        Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 16385));
                        thread.Start();

                        Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 16384, 32769));
                        thread2.Start();

                        Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 32768, 49153));
                        thread3.Start();

                        Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 49152, 65536));
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


            }
            //Run scan only on well-know ports
            else if (choice == "2")
            {
                Console.WriteLine("Starting well-known scan: ");
                try
                {
                    Thread thread = new Thread(() => multiIP(strippedIP, 1, 65, 1, 257));
                    thread.Start();

                    Thread thread2 = new Thread(() => multiIP(strippedIP, 64, 129, 256, 513));
                    thread2.Start();

                    Thread thread3 = new Thread(() => multiIP(strippedIP, 128, 193, 512, 769));
                    thread3.Start();

                    Thread thread4 = new Thread(() => multiIP(strippedIP, 192, 256, 768, 1024));
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
                            Thread thread = new Thread(() => selectedScan(strippedIP, Convert.ToInt32(portNumber)));
                            thread.Start();
                        }
                        DateTime finish = DateTime.Now;
                        timer.Stop();
                        TimeSpan ts = timer.Elapsed;
                        //Write results out to file
                        string totalTime = "Scanning finished at: " + Convert.ToString(finish) + "\r\n\r\n" + "Total scan time: " + Convert.ToString(ts);
                        File.AppendAllText(docPath + "\\results.txt", totalTime + Environment.NewLine);
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
                            Thread thread = new Thread(() => selectedScan(subnet, Convert.ToInt32(portNumber)));
                            thread.Start();
                        }
                        DateTime finish = DateTime.Now;
                        timer.Stop();
                        TimeSpan ts = timer.Elapsed;
                        //Write results out to file
                        string totalTime = "Scanning finished at: " + Convert.ToString(finish) + "\r\n\r\n" + "Total scan time: " + Convert.ToString(ts);
                        File.AppendAllText(docPath + "\\results.txt", totalTime + Environment.NewLine);
                    }


                }
            }
        }
    }
}
