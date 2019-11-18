using System;
using System.IO;
using System.Management;

namespace Neko.Discovery
{
    class GatherInfoUsingWMI
    {
        // WMI discovery
        public static void Parameters(string hostname, string Username, string Password, string domainURL, string nekoFolder, string wmiHost)
        {
            try
            {
                Console.WriteLine("Establishing WMI..");
                // Set connection options
                ConnectionOptions options = new ConnectionOptions();
                //Set impersonation level
                options.Impersonation = ImpersonationLevel.Impersonate;
                //Set username
                options.Username = Username;
                //Set password
                options.Password = Password;
                options.Authority = "ntlmdomain:" + GetDomainInfo.DomainURL;

                //Set scope
                ManagementScope scope = new ManagementScope("\\\\" + hostname + "\\root\\cimv2", options);
                scope.Connect();

                //Query system for Operating System information
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                //OS collection
                ManagementObjectCollection queryCollection = searcher.Get();

                //Get OS information
                try
                {
                    using (var writer = new StreamWriter(nekoFolder + wmiHost, append: true))
                    {
                        foreach (ManagementObject m in queryCollection)
                        {

                            string wmiScanResults = "Computer Name     : " + m["csname"] + "\r\n" +
                            "Operating System  : " + m["Caption"] + "\r\n" +
                            "Version           : " + m["Version"] + "\r\n" +
                            "Windows Directory : " + m["WindowsDirectory"] + "\r\n" +
                            "Manufacturer      : " + m["Manufacturer"] + "\r\n" +
                            "OS Architecture   : " + m["OSArchitecture"] + "\r\n";
                            ;

                            // Write out results
                            writer.WriteLine(wmiScanResults + Environment.NewLine);
                            writer.Flush();
                            Console.WriteLine(wmiScanResults);
                        }
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                // User Info
                ObjectQuery userQuery = new ObjectQuery("Select * FROM Win32_UserAccount");
                ManagementObjectSearcher userInfoSearch = new ManagementObjectSearcher(scope, userQuery);

                // User collection
                ManagementObjectCollection userCollection = userInfoSearch.Get();

                // Get user info
                try
                {

                    using (var writer = new StreamWriter(nekoFolder + wmiHost, append: true))
                    {
                        foreach (ManagementObject user in userCollection)
                        {
                            string userResults = "\r\nDomain: " + user["Domain"] + "\r\n" +
                               "Full Name: " + user["FullName"] + "\r\n" +
                               "Name: " + user["Name"] + "\r\n" +
                               "SID: " + user["SID"] + "\r\n" +
                               "Password Expires: " + user["PasswordExpires"] + "\r\n" +
                               "Password Changeable: " + user["PasswordChangeable"] + "\r\n\r\n";

                            //Write results
                            writer.WriteLine(userResults + Environment.NewLine);
                            writer.Flush();
                            Console.WriteLine(userResults);
                        }
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                // Logon Info
                ObjectQuery logonQuery = new ObjectQuery("Select * FROM Win32_LogonSession Where (LogonType = 2) OR (LogonType = 3)");
                ManagementObjectSearcher logonInfo = new ManagementObjectSearcher(scope, logonQuery);

                // User collection
                ManagementObjectCollection logonCollection = logonInfo.Get();

                // Get logon info
                try
                {

                    using (var writer = new StreamWriter(nekoFolder + wmiHost, append: true))
                    {
                        foreach (ManagementObject logon in logonCollection)
                        {
                            string logonResults = "Logon info: " + logon["Name"] + "\r\n" + "UserName: " + logon["UserName"] +
                                "Start: " + Convert.ToString(DateTime.FromFileTime((long)logon["StartTime"])) + "\r\n" +
                                "Status: " + logon["Status"] + "\r\n" +
                                "Authentication: " + logon["AuthenticationPackage"] + "\r\n" +
                                "Logon ID: " + logon["LogonId"] + "\r\n" +
                                "Logon Type: " + logon["LogonType"] + "\r\n\r\n";

                            //Write results
                            writer.WriteLine(logonResults + Environment.NewLine);
                            writer.Flush();
                            Console.WriteLine(logonResults);
                        }
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }


                // Computer System
                ObjectQuery computerQuery = new ObjectQuery("Select * FROM Win32_ComputerSystem");
                ManagementObjectSearcher computerInfo = new ManagementObjectSearcher(scope, computerQuery);

                // User collection
                ManagementObjectCollection computerCollection = computerInfo.Get();

                // Get logon info
                try
                {
                    //File.AppendAllText(nekoFolder + "\\Network Scan Reults.txt", results + Environment.NewLine + Environment.NewLine);

                    using (var writer = new StreamWriter(nekoFolder + wmiHost, append: true))
                    {
                        foreach (ManagementObject User in computerCollection)
                        {
                            string UserResults = "UserName: " + User["UserName"] + "\r\n" +
                                "Primary Owner Name: " + User["PrimaryOwnerName"] + "\r\n" +
                                "Name: " + User["Name"] + "\r\n" +
                                "Model: " + User["Model"] + "\r\n" +
                                "Manufacturer: " + User["Manufacturer"] + "\r\n" +
                                "LastLoadInfo: " + User["LastLoadInfo"] + "\r\n" +
                                "BootupState: " + User["BootupState"] + "\r\n" +
                                "Status: " + User["Status"] + "\r\n\r\n";

                            //Write results
                            writer.WriteLine(UserResults + Environment.NewLine);
                            writer.Flush();
                            Console.WriteLine(UserResults);
                        }
                    }
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e + "Access Denied, insufficient privileges");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            // Catch access denied error
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine(e + "Access Denied, insufficient privileges. Confirm domain admin privileges.");
            }
            // Catch local machine error
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
