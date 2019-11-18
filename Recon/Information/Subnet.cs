using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Neko.Information
{
    class Subnet
    {
        // Get default network gateway
        public static IPAddress GetDefaultGateway()
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                .FirstOrDefault();
        }

        // Checks if IP address is valid
        public static bool ValidateIP(string ipString)
        {
            if (ipString.Count(c => c == '.') != 3) return false;
            IPAddress address;
            return IPAddress.TryParse(ipString, out address);
        }

        // Function to check IP user wants to use
        public static string UserIpChoice(string defaultGateway)
        {
            // Tell user thier gatway and check if they want to use that or a specified network
            Console.WriteLine("\r\nYour default gateway is " + defaultGateway + " Would you like to scan this subnet? Enter 'y' or 'n':");
            string whichNetwork = Console.ReadLine();
            string subnet = "";
            while (whichNetwork != "y" && whichNetwork != "n")
            {
                Console.WriteLine("\r\nInvalid choice. Your default gateway is " + defaultGateway + " Would you like to scan this subnet? Enter 'y' or 'n':");
                whichNetwork = Console.ReadLine();
            }
            if (whichNetwork == "y")
            {
                subnet = defaultGateway;
                // Validate that the IP is correct format
                ValidateIP(subnet);
            }
            else if (whichNetwork == "n")
            {
                Console.WriteLine("\r\nPlease enter a subnet to scan. For example, '192.168.0.1':");
                subnet = Console.ReadLine();
                // Validate that the IP is in correct format
                if (ValidateIP(subnet) == false)
                {
                    Console.WriteLine("Invalid IP. Please enter a subnet to scan. For example, '192.168.0.1':");
                }
            }
            return subnet;
        }

        // Validate IP
        public static string StripIP(string subnet)
        {
            // Split IP into array
            string[] splitAddress = subnet.Split('.');

            // Joins IP back together without the 4th octet
            string strippedIP = string.Join(".", splitAddress, 0, 3) + ".";
            return strippedIP;
        }
    }
}
