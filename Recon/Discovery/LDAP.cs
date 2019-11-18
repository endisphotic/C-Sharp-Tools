using System;
using System.IO;
using Neko.Exfiltration;

namespace Neko.Discovery
{
    class LDAP
    {
        public static void Information()
        {
            // Confirm that it is correct
            Console.WriteLine("\r\n" +
                "Recon will begin on: " + GetDomainInfo.DomainURL + "." + " Is this correct? Enter 'y' or 'n':");
            string ldapConfirmation = Console.ReadLine();
            while (ldapConfirmation != "y" && ldapConfirmation != "n")
            {
                Console.WriteLine("\r\n" +
                    "Invalid selection. Recon will begin on: " + GetDomainInfo.DomainURL + " Is this correct? Enter 'y' or 'n':");
            }
            // If user wants to use a different domain, get that one.
            if (ldapConfirmation == "n")
            {
                // Get info for domain
                Console.WriteLine("\r\nPlease enter the domain for searching:");
                GetDomainInfo.DomainURL = Console.ReadLine();
            }

            try
            {
                // Active Directory Recon
                var usersList = ADUser.GetUsers("LDAP://" + GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
                Console.WriteLine("\r\nFound users: ");
                // Queries LDAP and writes out info to console and results

                // Get unique file to prevent overwriting
                string writePath = UniqueFileCheck.UniqueFile(SaveLocations.NekoFolder + "\\LDAP User Recon.csv");

                // Start stream writer for writing results
                using (var writer = new StreamWriter(writePath, append: true))
                {
                    foreach (var userAccount in usersList)
                    {
                        Console.WriteLine(userAccount.SamAccountName);
                        Console.WriteLine(userAccount.SID);
                        Console.WriteLine(userAccount.FirstName);
                        Console.WriteLine(userAccount.LastName);
                        Console.WriteLine(userAccount.StreetAddress);
                        Console.WriteLine(userAccount.DirectReports);
                        Console.WriteLine(userAccount.LastLogon);
                        Console.WriteLine(userAccount.LastLogoff);
                        Console.WriteLine(userAccount.MemberOf);
                        Console.WriteLine(userAccount.AdminCount);

                        // Write out results
                        writer.WriteLine(Environment.NewLine + "\r\nSAM Account: " + userAccount.SamAccountName + Environment.NewLine + "Account SID: " + userAccount.SID +
                        Environment.NewLine + "First Name: " + userAccount.FirstName + Environment.NewLine + "Last Name: " + userAccount.LastName + Environment.NewLine +
                        "Street Address: " + userAccount.StreetAddress + Environment.NewLine + "Director Reports: " + userAccount.DirectReports + Environment.NewLine +
                        "Last Logon: " + userAccount.LastLogon + Environment.NewLine + "Last Logoff: " + userAccount.LastLogoff + Environment.NewLine + "Member of: " +
                        userAccount.MemberOf + Environment.NewLine + "Admin Count: " + userAccount.AdminCount);
                        writer.Flush();

                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            try
            {
                // Create list of computers
                var computerList = Neko.ADComputer.GetADComputers(GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
                Console.WriteLine("\r\nFound computers:");

                // Get unique file to prevent overwriting
                string writePath = UniqueFileCheck.UniqueFile(SaveLocations.NekoFolder + "\\LDAP Computer Recon.txt");

                // Start stream writer for writing results
                using (var writer = new StreamWriter(writePath, append: true))
                {
                    foreach (var computer in computerList)
                    {
                        Console.WriteLine(computer.ComputerInfo);
                        Console.WriteLine(computer.LastLogon);
                        Console.WriteLine(computer.ComputerType);

                        // Write out results
                        writer.WriteLine(Environment.NewLine + "Computer Name: " + computer.ComputerInfo + Environment.NewLine + "Last Logon: " + computer.LastLogon
                            + Environment.NewLine + "Computer type " + computer.ComputerType);
                        writer.Flush();

                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

        }
    }
}
