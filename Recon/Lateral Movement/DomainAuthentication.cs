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
using System.Text.RegularExpressions;
using System.Net.NetworkInformation;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Security.Permissions;
using Microsoft.Win32;
using Neko;

namespace Neko
{
    class DomainAuthentication
    {
        // Declare user and password variables
        public static string Username = "";
        public static string Password = "";

        // Attempt to authenticate, still need to debug after moving into its own class
        public static bool Authenticate()
        {
            Console.WriteLine("\r\nPlease specify the username and password for use: ");

            Console.WriteLine("\r\n" +
                            "Enter user name:");
            Username = Console.ReadLine();
            //Password
            Console.WriteLine("\r\n" +
                "Enter password:");
            Password = Console.ReadLine();

            //if program was unable to get domain, get domain info
            if (GetDomainInfo.DomainURL == "")
            {
                Console.WriteLine("\r\nPlease enter the domain for searching:");
                GetDomainInfo.DomainURL = Console.ReadLine();
            }
            else
            {
                Console.WriteLine("\r\nDo you want to use " + GetDomainInfo.DomainURL + "? Enter 'y' or 'n': ");
                string confirmDomain = Console.ReadLine();
                while (confirmDomain != "y" && confirmDomain != "n")
                {
                    Console.WriteLine("\r\nInvalid selection. Do you want to use " + GetDomainInfo.DomainURL + " ? Enter 'y' or 'n': ");
                    confirmDomain = Console.ReadLine();
                }
                //If user wants to use a different domain, get it.
                if (confirmDomain == "n")
                {
                    Console.WriteLine("\r\nPlease enter the domain for searching:");
                    GetDomainInfo.DomainURL = Console.ReadLine();
                }
            }
            //Don't move forward until authentication succeeds. 
            bool ValidCreds = false;
            //Set context
            while (ValidCreds == false)
            {
                try
                {
                    PrincipalContext accountCheck = new PrincipalContext(ContextType.Domain, GetDomainInfo.DomainURL);

                    if (accountCheck.ValidateCredentials(Username, Password) == true)
                    {
                        Console.WriteLine("\r\nAuthenication successful!");
                        //Information verified proceeding to next step 
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("\r\nInvalid username or password.");
                        Console.WriteLine("Please enter valid username and password: ");
                        Console.WriteLine("Username: ");
                        Username = Console.ReadLine();
                        Console.WriteLine("Password: ");
                        Password = Console.ReadLine();
                    }

                }
                catch (PrincipalServerDownException e)
                {
                    if (e.Message.Contains("server could not"))
                    {
                        Console.WriteLine("Server could not be contacted.\r\nPlease specify a valid domain or enter 'exit': ");
                        GetDomainInfo.DomainURL = Console.ReadLine();
                        if (GetDomainInfo.DomainURL == "exit")
                        {
                            //Break out of loop if user enters exit and return to beginning
                            break;
                        }
                    }
                    return false;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            return true;
        }
    }
}
