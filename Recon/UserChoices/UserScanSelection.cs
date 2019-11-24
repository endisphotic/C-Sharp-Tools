using System;
using System.Collections.Generic;

namespace Neko.UserChoices
{
    class UserScanSelection
    {
        public static string DiscoveryScanType = string.Empty;

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
        }

        // List for WMI targets if found
        public static List<string> WMITargets = new List<string>();
    }
}
