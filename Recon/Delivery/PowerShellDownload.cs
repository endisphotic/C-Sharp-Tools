using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Neko.Delivery
{
    class PowerShell
    {
        public static void DownloadFile()
        {
            Console.WriteLine("\r\n" +
            "Install payload on selected WMI targets via PowerShell? Enter 'y' or 'n' or 'exit':");
            string targetWmi = Console.ReadLine();
            //Confirm that user wants to do this action
            while (targetWmi != "y" && targetWmi != "n" && targetWmi != "exit")
            {
                Console.WriteLine("\r\n" +
                    "Install payload on selected WMI targets via PowerShell? Enter 'y' or 'n' or 'exit':");
                targetWmi = Console.ReadLine();
            }
            if (targetWmi == "y")
            {
                //Check that user has domain admin creds
                Console.WriteLine("\r\n This process requires Domain Admin credentials, proceed? Enter 'y' or 'n':");
                string hasDomain = Console.ReadLine();
                while (hasDomain != "y" && hasDomain != "n")
                {
                    Console.WriteLine("\r\n" +
                        "Invalid selection. This process requires Domain Admin credentials, proceed? Enter 'y' or 'n':");
                    hasDomain = Console.ReadLine();
                }
                if (hasDomain == "y")
                {
                    //Tell user their domain and confirm that this is the intended domain
                    Console.WriteLine("\r\n" +
                        "Your domain is: " + GetDomainInfo.DomainURL + " Would you like to continue using this domain? Enter 'y' or 'n':");
                    string domainConfirmation = Console.ReadLine();
                    while (domainConfirmation != "y" && domainConfirmation != "n")
                    {
                        Console.WriteLine("Invalid selection. Your domain is: " + GetDomainInfo.DomainURL + " Would you like to continue using this domain? Enter 'y' or 'n':");
                        domainConfirmation = Console.ReadLine();
                    }
                    if (domainConfirmation == "n")
                    {
                        Console.WriteLine("Please enter new domain to use:");
                        GetDomainInfo.DomainURL = Console.ReadLine();
                    }

                    // Get target list
                    Console.WriteLine("\r\n" +
                        "Enter target IP addresses separated by commas:");
                    // Get IP targets
                    string ipTargets = Console.ReadLine();

                    // Split into array by commas
                    string[] ipSplit = ipTargets.Split(',');

                    // Declare command
                    string commandFile = "";
                    Console.WriteLine("\r\n" +
                        "Enter remote command, for example, Notepad.exe, Dir, Shutdown -r:");
                    // Get command from user
                    commandFile = Console.ReadLine();

                    // Attack targets
                    foreach (string target in ipSplit)
                    {
                        UserChoices.WMIAttack.Parameters(DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, target, commandFile);
                    }
                }
            }
        }
    }
}
