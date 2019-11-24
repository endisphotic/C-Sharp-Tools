using System;
using Neko.Discovery.PortScanning;

namespace Neko
{
    class UserSelections
    {
        static string DiscoveryScanType = string.Empty;
        
        // Function for what type of scan
        public static string ScanSelection()
        {
            Console.WriteLine("\r\nPlease select scan type: type '1' for WMI + Network (REQUIRES Domain Admin credentials) or '2' for Network ONLY:");
            DiscoveryScanType = Console.ReadLine();

            while (DiscoveryScanType != "1" && DiscoveryScanType != "2")
            {
                Console.WriteLine("\r\nInvalid selection. Please select scan type: type '1' for WMI + Network (REQUIRES Domain Admin credentials) or '2' for Network ONLY:");
                DiscoveryScanType = Console.ReadLine();
            }
            return DiscoveryScanType;

            // Conduct scan
            PortChoices.Selections();
        } 

        public static readonly string ScanType = ScanSelection();
    }
}
