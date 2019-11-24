using System;

namespace Neko.UserChoices
{
    class AttackType
    {
        public static string attackType = string.Empty;

        public static string Selection()
        {
            // Prompt user decision on recon or deployment via WMI
            Console.WriteLine("\r\nNeko Attack Options: \r\n\r\n 1: Discovery \r\n\r\n 2: Installation \r\n\r\n 3: Execution via WMI \r\n\r\n 4: Command and Control" +
                "\r\n\r\n 5: Remote Registry Tampering");
            Console.WriteLine("\r\nMake your selection:");
            attackType = Console.ReadLine();
            while (attackType != "1" && attackType != "2" && attackType != "3" && attackType != "4")
            {
                Console.WriteLine("\r\nInvalid selection. Enter '1' for Recon, '2' Deployment via WMI:");
                attackType = Console.ReadLine();
            }

            // Set save location for data exfiltration
            string nekoFolder = Exfiltration.SaveLocations.SetPath();

            LaunchAttack(attackType);
            return attackType;
        }

        public static void LaunchAttack(string attackType)
        {
            // Discovery
            if (attackType == "1")
            {
                DiscoveryChoice.Selections();
            }
            // Installation of payload via PowerShell + WMI with obfuscation options
            else if (attackType == "2")
            {
                Delivery.PowerShell.DownloadFile();
            }
            // User choice to deploy via WMI
            else if (attackType == "3")
            {
                Execution.WMIDeployment.Deploy();
            }
            // C2 via Reverse TCP Shell
            else if (attackType == "4")
            {
                Command_and_Control.ReverseTCPShell.Control();
            }
            // Remote registry tampering
            else if (attackType == "5")
            {
                RemoteRegistry.RegModification(Exfiltration.SaveLocations.NekoFolder, GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
            }
        }
    }
}
