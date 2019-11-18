using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Net;
using System.Management;
using System.Text.RegularExpressions;
using System.Net.NetworkInformation;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Security.Permissions;
using Microsoft.Win32;

namespace Neko
{
    class UniqueFileCheck
    {
        //Check if file exists, and if so add next number method
        public static string UniqueFile(string resultsPath)
        {

            //Check if file exists
            if (File.Exists(resultsPath))
            {
                //Get folder path
                string folder = Path.GetDirectoryName(resultsPath);
                //Get file name
                string filename = Path.GetFileNameWithoutExtension(resultsPath);
                //Get extension of file
                string extension = Path.GetExtension(resultsPath);

                //Set number
                int fileNumber = 1;

                //Regex pattern for matchin
                Match regex = Regex.Match(resultsPath, @"(.+) \((\d+)\)\.\w+");

                if (regex.Success)
                {
                    filename = regex.Groups[1].Value;
                    fileNumber = int.Parse(regex.Groups[2].Value);
                }

                do
                {
                    //Keep adding numbers until file can be created
                    fileNumber++;
                    resultsPath = Path.Combine(folder, string.Format("{0} ({1}){2}", filename, fileNumber, extension));
                }
                while (File.Exists(resultsPath));
            }
            return resultsPath;

        }
    }
}
