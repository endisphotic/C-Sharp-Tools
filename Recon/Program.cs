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

            //Create stopwatch
            Stopwatch timer = new Stopwatch();

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

                while (choice != "1" && choice != "2" && choice != "3" && choice != "exit")
                {
                    Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, and 3 for selected port scan or 'exit': ");
                    choice = Console.ReadLine();
                }
                //Run scan on all ports
                if (choice == "1")
                {
                    Console.WriteLine("Starting full scan: ");
                    try
                    {
                        timer.Start();
                        for (int i = 1; i < 256; i++)
                        {
                            for (int j = 1; j < 65536; j++)

                                fullScan(strippedIP + Convert.ToString(i), j);
                        }
                        DateTime finish = DateTime.Now;
                        timer.Stop();
                        TimeSpan ts = timer.Elapsed;
                        string totalTime = "Scanning finished at: " + Convert.ToString(finish) + "\r\n\r\n" + "Total scan time: " + Convert.ToString(ts);
                        File.AppendAllText(docPath + "\\results.txt", totalTime + Environment.NewLine);

                    }
                    catch
                    {

                    }
                }
                //Run scan only on well-know ports
                else if (choice == "2")
                {
                    Console.WriteLine("Starting well-known scan: ");
                    try
                    {
                        timer.Start();
                        for (int i = 1; i < 256; i++)
                        {
                            for (int j = 1; j < 1024; j++)

                                fullScan(strippedIP + Convert.ToString(i), j);
                        }
                        DateTime finish = DateTime.Now;
                        timer.Stop();
                        TimeSpan ts = timer.Elapsed;
                        string totalTime = "Scanning finished at: " + Convert.ToString(finish) + "\r\n\r\n" + "Total scan time: " + Convert.ToString(ts);
                        File.AppendAllText(docPath + "\\results.txt", totalTime + Environment.NewLine);
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
        public static void fullScan(string hostname, int port)
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

    }
}
