using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.IO;
using System.Threading;

namespace Recon
{
	class Program
	{
		static void Main(string[] args)
		{

            //DateTime now = DateTime.Now;


			Console.WriteLine("Please enter the first three octects for the scan range, for example, '192.168.0.' :");
			string computerName = Console.ReadLine();

            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "results.txt")))
            {
                outputFile.WriteLine("Results of Recon: ");
            }

            Console.WriteLine("Please enter 1 for full port scan, 2 for well-known port scan, and 3 for selected port scan: ");
            string choice = Console.ReadLine();
            if (choice == "1")
            {
                Console.WriteLine("Starting full scan: ");
                try
                {
                    for (int i = 1; i < 256; i++)
                    {
                        for(int j = 1; j < 65536; j++)

                        fullScan(computerName + Convert.ToString(i), j);
                    }
                    //string scanDuration = 
                }
                catch
                {

                }
            }
            else if(choice == "2")
            {
                Console.WriteLine("Starting well-known scan: ");
                try
                {
                    for (int i = 1; i < 256; i++)
                    {
                        for (int j = 1; j < 1024; j++)

                            fullScan(computerName + Convert.ToString(i), j);
                    }
                }
                catch
                {

                }
            }
            else if (choice == "3")
            {
                //Get port number from user
                Console.WriteLine("Please enter port numbers separated by commas: ");
                string ports = Console.ReadLine();

                if (ports == "")
                {
                    Console.WriteLine("Please enter port numbers separated by commas: ");
                }
                else
                {
                    List<int> portList = new List<int>();
                    string[] fullList = ports.Split(',');
                    foreach(var portNumber in fullList)
                    {
                        portList.Add(Convert.ToInt32(portNumber));
                    }

                    foreach(var portNumber in fullList)
                    {
                        Thread thread = new Thread(() => selectedScan(computerName, Convert.ToInt32(portNumber)));
                        thread.Start();
                    }
                    
                    
                }
            }
            else
            {
                Console.WriteLine("Closing");
            }
		
		}


        public static void selectedScan(string hostname, int port)
        {

            
            //string computerName = Console.ReadLine();
            string results = "";
            Console.WriteLine("Starting selected scan on port: " + Convert.ToString(port));
            //try
            // {
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
                    //Console.WriteLine(e);
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

    }
}
