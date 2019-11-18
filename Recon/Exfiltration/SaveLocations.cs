using System;
using System.IO;

namespace Neko.Exfiltration
{
    class SaveLocations
    { 
        public static string SetPath()
        {
            //Create document path for scan results
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            //Create sub folder
            string nekoFolder = Path.Combine(docPath, "Neko");

            if (!File.Exists(nekoFolder))
            {
                //Create folder for results if it doesn't exist
                Directory.CreateDirectory(nekoFolder);
            }

            Console.WriteLine("\r\nResults will be written to " + nekoFolder);
            return nekoFolder;
        }

        public static string NekoFolder = SetPath();
    }
}
