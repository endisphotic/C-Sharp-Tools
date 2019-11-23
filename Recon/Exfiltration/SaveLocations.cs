using System;
using System.IO;

namespace Neko.Exfiltration
{
    class SaveLocations
    {
        //Create document path for scan results
        static string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        //Create sub folder
        static string nekoFolder = Path.Combine(docPath, "Neko");

        public static string SetPath()
        {
            if (!File.Exists(nekoFolder))
            {
                //Create folder for results if it doesn't exist
                Directory.CreateDirectory(nekoFolder);
            }

            Console.WriteLine("\r\nResults will be written to " + nekoFolder);
            return nekoFolder;
        }

        public static string NekoFolder = nekoFolder;
    }
}
