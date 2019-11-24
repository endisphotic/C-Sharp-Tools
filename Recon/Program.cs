using System;
using Neko;
using Neko.UserChoices;

namespace Recon
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("Welcome to Neko \r\n", Console.ForegroundColor = ConsoleColor.Green);
            Console.ResetColor();
            Console.Write(@"                      _                        
                      \`*-.
                       )  _`-.
                      .  : `. .                
                      : _   '  \               
                      ; *` _.   `*-._
                      `-.- '          `-.       
                        ;       `       `.     
                        :.       .        \    
                        . \  .   :   .-'   .   
                        '  `+.;  ;  '      :   
                        :  '  |    ;       ;-. 
                        ; '   : :`-:     _.`* ;
                      .* ' /  .*'; .*`-+'  `*'
                     `*-*   `*-*  `*-*'    ");
            Console.WriteLine("\r\n\r\nThis is a tool designed for various pen-testing activities on the local machine and remote machines if Active Directory components are selected.",
                Console.ForegroundColor = ConsoleColor.Magenta);
            Console.ResetColor();

            bool infoConfirmed = false;

            // Attempt to get domain information
            GetDomainInfo.DomainAuthentication();

            while (infoConfirmed == false)
            {
                Console.WriteLine("\r\nWill you be using any Active Directory components, such as LDAP recon, remote registry, or lateral movement via WMI? \r\n\r\nEnter 'y' or 'n':");
                string adCheck = Console.ReadLine();
                while (adCheck != "y" && adCheck != "n")
                {
                    Console.WriteLine("\r\nInvalid selection. Enter 'y' or 'n':");
                    adCheck = Console.ReadLine();
                }

                // Check if authentication to AD is required
                if (adCheck == "y")
                {
                    if (DomainAuthentication.Authenticate() == true)
                    { 
                        break;
                    }
                }
                else if (adCheck == "n")
                {
                    // Information verified proceeding to next step. 
                    infoConfirmed = true;
                }
            }

            // Get attack type
            AttackType.Selection();

            bool done = false;
            while (!done)
            {
                // See if user wants to go back to main menu or exit
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
                // Send user back to main menu
                if (mainMenu == "m")
                {
                    // Clear console
                    Console.Clear();
                    AttackType.Selection();
                }
            }
        }
    }   
}
