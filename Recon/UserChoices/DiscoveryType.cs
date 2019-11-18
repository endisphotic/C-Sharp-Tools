﻿using System;

namespace Neko.UserChoices
{
    class DiscoveryChoice
    {
        static readonly string DiscoverySelection = string.Empty;

        public static string Selections()
        {
            Console.WriteLine("\r\nRecon options: \r\n\r\n 1: Local machine \r\n\r\n 2: Domain via LDAP \r\n\r\n 3: Network Scan with Option of WMI" +
            "\r\n\r\n 4: Remote Registry");
            string DiscoverySelection = Console.ReadLine();
            while (DiscoverySelection != "1" && DiscoverySelection != "2" && DiscoverySelection != "3" && DiscoverySelection != "4")
            {
                Console.WriteLine("\r\n" +
                    "Invalid selection. Enter '1' for Local machine, '2' for Domain, or '3' for Network IP Scan with Option of WMI");
                DiscoverySelection = Console.ReadLine();
            }
            return DiscoverySelection;
        }

        public static void Options()
        {
            //Local machine recon
            if (DiscoverySelection == "1")
            {
                Console.WriteLine("\r\n" +
                    "Conduct local system recon? Enter 'y' or 'n' or 'exit':");
                string machineInfo = Console.ReadLine();
                while (machineInfo != "y" && machineInfo != "n")
                {
                    Console.WriteLine("\r\n" +
                        "Invalid selection. Do you want to do network recon via LDAP? Enter 'y' or 'n':");
                    machineInfo = Console.ReadLine();
                }
                //Conduct local recon
                LocalMachineRecon.LocalMachine(Exfiltration.SaveLocations.NekoFolder);
            }
            //Domain recon via LDAP
            else if (DiscoverySelection == "2")
            {

                //See if user wants to do LDAP searching
                Console.WriteLine("\r\n" +
                    "Do you want to do domain recon via LDAP? Enter 'y' or 'n':");
                string ldapQueries = Console.ReadLine();
                while (ldapQueries != "y" && ldapQueries != "n")
                {
                    Console.WriteLine("\r\n" +
                        "Invalid selection. Do you want to do network recon via LDAP? Enter 'y' or 'n':");
                    ldapQueries = Console.ReadLine();
                }

                //If user opts to run ldap queries 
                if (ldapQueries == "y")
                {
                    Discovery.LDAP.Information();
                }
            }
            //Network IP recon with option of WMI
            else if (DiscoverySelection == "3")
            {
                //Get type of scan
                var scanType = UserSelections.ScanSelection();


                // Get WMI User Info
                if (scanType == "1")
                {
                    Console.WriteLine("\r\n" +
                        "This process typically requires Domain Admin credentials, does " + DomainAuthentication.Username + " have sufficient credentials? Enter 'y' or 'n':");
                    string hasDomainAdmin = Console.ReadLine();
                    while (hasDomainAdmin != "y" && hasDomainAdmin != "n")
                    {
                        Console.WriteLine("\r\n" +
                            "Invalid selection. This process requires Domain Admin credentials, proceed? Enter 'y' or 'n':");
                        hasDomainAdmin = Console.ReadLine();
                    }
                    if (hasDomainAdmin == "n")
                    {
                        Console.WriteLine("\r\n" +
                            "Enter user name:");
                        DomainAuthentication.Username = Console.ReadLine();
                        //Password
                        Console.WriteLine("\r\n" +
                            "Enter password:");
                        DomainAuthentication.Password = Console.ReadLine();
                    }

                    //If LDAP querying was not done, gets domain to use for WMI
                    if (GetDomainInfo.DomainURL == "")
                    {
                        Console.WriteLine("\r\n" +
                            "Enter network domain:");
                        GetDomainInfo.DomainURL = Console.ReadLine();
                    }
                    //If ldap querying was done, confirms they want to use the same domain
                    else
                    {

                        Console.WriteLine("\r\n" +
                            "The domain selected for LDAP recon was: " + GetDomainInfo.DomainURL + " Would you like to continue using this domain? Enter 'y' or 'n':");
                        string domainConfirmation = Console.ReadLine();
                        while (domainConfirmation != "y" && domainConfirmation != "n")
                        {
                            Console.WriteLine("\r\n" +
                                "Invalid selection. The domain selected for LDAP recon was: " + GetDomainInfo.DomainURL + " Would you like to continue using this domain? Enter 'y' or 'n':");
                            domainConfirmation = Console.ReadLine();
                        }
                        //If they select n, they're prompted for a different domain
                        if (domainConfirmation == "n")
                        {
                            Console.WriteLine("Please enter new domain to use:");
                            GetDomainInfo.DomainURL = Console.ReadLine();
                        }
                    }
                }
            }
            else if (DiscoverySelection == "4")
            {
                RemoteRegistry.RegQuery(Exfiltration.SaveLocations.NekoFolder, GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
            }
        }
    }
}
