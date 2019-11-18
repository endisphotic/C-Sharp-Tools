using System;
using Neko;
using Neko.UserChoices;
using Neko.Exfiltration;

namespace Recon
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("Welcome to Neko. \r\n");

            bool infoConfirmed = false;

            // Attempt to get domain information
            GetDomainInfo.DomainAuthentication();

            while (infoConfirmed == false)
            {
                Console.WriteLine("Will you be using any Active Directory components, such as LDAP recon, remote registry, or lateral movement via WMI? \r\n\r\nEnter 'y' or 'n':");
                string adCheck = Console.ReadLine();
                while (adCheck != "y" && adCheck != "n")
                {
                    Console.WriteLine("\r\nInvalid selection. Enter 'y' or 'n':");
                    adCheck = Console.ReadLine();
                }

                if (adCheck == "y")
                {
                    DomainAuthentication.Authenticate();
                }
                else if (adCheck == "n")
                {
                    //Information verified proceeding to next step. 
                    infoConfirmed = true;
                }
            }

            // Set save location for data exfiltration
            string nekoFolder = SaveLocations.SetPath();

            // Get attack type
            AttackType.Selection();

            // Execute attack
            AttackType.LaunchAttack();

            // Set discovery options
            DiscoveryChoice.Options();

            bool done = false;
            while (!done)
            {
                //See if user wants to go back to main menu or exit
                Console.WriteLine("\r\n" +
                    "Enter 'm' for Main Menu or 'e' for exit:");
                string mainMenu = Console.ReadLine();
                while (mainMenu != "m" && mainMenu != "e")
                {
                    Console.WriteLine("Invalid selection. Enter 'm' for Main Menu or 'e' for exit:");
                    mainMenu = Console.ReadLine();
                }
                if (mainMenu == "e")
                {
                    done = true;
                }
                //Send user back to main menu
                if (mainMenu == "m")
                {
                    //Clear console
                    Console.Clear();
                }
            }
        }
    }   
}
