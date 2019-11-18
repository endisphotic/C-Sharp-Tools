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
using Neko;

namespace Neko
{
    class GetDomainInfo
    {
        public static string DomainURL = "";
        
        public static void DomainAuthentication()
        {
            try
            {
                Domain domain = Domain.GetComputerDomain();
                DomainURL = domain.Name;
            }
            catch
            {

            }
        }
    }
}
