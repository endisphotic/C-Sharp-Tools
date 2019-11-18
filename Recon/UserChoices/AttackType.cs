using System;

namespace Neko.UserChoices
{
    class AttackType
    {
        public static string Selection()
        {
            //Prompt user decision on recon or deployment via WMI
            Console.WriteLine("\r\nOptions: \r\n\r\n 1: Discovery \r\n\r\n 2: Installation from C2 via WMI + PowerShell \r\n\r\n 3: Deployment via WMI \r\n\r\n 4: Command and Control \r\n" +
                "\r\n\r\n 5: Remote Registry Tampering");
            Console.WriteLine("Make your selection:");
            string attackType = Console.ReadLine();
            while (attackType != "1" && attackType != "2" && attackType != "3" && attackType != "4")
            {
                Console.WriteLine("\r\nInvalid selection. Enter '1' for Recon, '2' Deployment via WMI:");
                attackType = Console.ReadLine();
            }
            return attackType;
        }

        public static readonly string UserSelection = Selection();

        public static void LaunchAttack()
        {
            // Discovery
            if (UserSelection == "1")
            {
                DiscoveryChoice.Options();
            }
            //Installation of payload via PowerShell + WMI with obfuscation options
            else if (UserSelection == "2")
            {
                Delivery.PowerShell.DownloadFile();
            }
            //User choice to deploy via WMI
            else if (UserSelection == "3")
            {
                Execution.WMIDeployment.Deploy();
            }
            //C2 via Reverse TCP Shell
            else if (UserSelection == "4")
            {
                Command_and_Control.ReverseTCPShell.Control();
            }
            //Remote registry tampering
            else if (UserSelection == "5")
            {
                RemoteRegistry.RegModification(Exfiltration.SaveLocations.NekoFolder, GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
            }
        }
    }
}
