using System;
using System.IO;
using Microsoft.Win32;

namespace Neko
{
    class RemoteRegistry
    {

        /// Method for remote registry query for logged on users - need to make this so user can input their own options
        public static void RegQuery(string nekoFolder, string domainURL, string Username, string Password)
        {
            //Confirm that user has appropriate creds and is able to query registry remotely. 
            Console.WriteLine("This process typically requires domain admin privileges and remote registry enabled. Conintue? Enter 'y' or 'n':");
            string userDecision = Console.ReadLine();
            while (userDecision != "y" && userDecision != "")
            {
                Console.WriteLine("Invalid Selection.\r\nThis process typically requires domain admin privileges and remote registry enabled. Conintue? Enter 'y' or 'n':");
            }
            if (userDecision == "y")
            {

                //Need to turn this into list from previous results
                Console.WriteLine("Enter '1' to use results from LDAP recon or '2' to specify target computer name:");
                userDecision = Console.ReadLine();
                while (userDecision != "1" && userDecision != "2")
                {
                    Console.WriteLine("Invalid selection.\r\nEnter '1' to use results from LDAP recon or '2' to specify target computer name:");
                }

                if (userDecision == "2")
                {

                    //Declare computer name
                    string computerName = "";
                    //Get computer name
                    Console.WriteLine("Specify target computer name:");
                    computerName = Console.ReadLine();

                    //Open remote key
                    try
                    {
                        //Specifiy key
                        RegistryKey registryKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName, RegistryView.Registry64);

                        var key = registryKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
                        if (key == null)
                        {

                        }
                        //Create objects for values
                        object lastUser = key.GetValue("LastLoggedOnUser");
                        object lastDisplayName = key.GetValue("LastLoggedOnDisplayName");

                        //Display information
                        Console.WriteLine(lastUser.ToString(), lastDisplayName.ToString());

                        //Write out results
                        File.AppendAllText(nekoFolder + "\\User Locations.txt", "Last user: " + lastUser.ToString() + Environment.NewLine + "Display Name: " + lastDisplayName.ToString() + Environment.NewLine
                            + "Computer Name: " + computerName + Environment.NewLine);


                    }
                    catch (UnauthorizedAccessException e)
                    {
                        Console.WriteLine("Access Denied. Insuficient privileges.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
                else
                {
                    //ComputerName from list
                    //Access list class from LDAP recon, need to make this so user can specify their own list if they want.
                    Console.WriteLine("Have you run LDAP recon to generate machine name list? Enter 'y' or 'n'");
                    string userChoice = Console.ReadLine();
                    while (userChoice != "y" && userChoice != "n")
                    {
                        Console.WriteLine("Invalid selection. Have you run LDAP computer recon to generate machine name list? Enter 'y' or 'n'");
                        //Set input
                        userChoice = Console.ReadLine();
                    }
                    //Run ldap comnputer recon
                    if (userChoice == "n")
                    {
                        try
                        {
                            var computerList = Neko.ADComputer.GetADComputers(domainURL, Username, Password);
                            Console.WriteLine("\r\nFound computers:");

                            //Get unique file to prevent overwriting
                            string writePath = UniqueFileCheck.UniqueFile(nekoFolder + "\\LDAP Computer Recon.txt");

                            //Start stream writer for writing results
                            using (var writer = new StreamWriter(writePath, append: true))
                            {
                                foreach (var computer in computerList)
                                {
                                    Console.WriteLine(computer.ComputerInfo);
                                    Console.WriteLine(computer.LastLogon);
                                    Console.WriteLine(computer.ComputerType);

                                    //Write out results
                                    writer.WriteLine(Environment.NewLine + "Computer Name: " + computer.ComputerInfo + Environment.NewLine + "Last Logon: " + computer.LastLogon
                                        + Environment.NewLine + "Computer type " + computer.ComputerType);
                                    writer.Flush();
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                    }
                    //Run remote registry recon for all machines in list. 
                    else
                    {
                        var computerList = Neko.ADComputer.GetADComputers(domainURL, Username, Password);

                        foreach (var computerName in computerList)
                        {
                            //Open remote key
                            try
                            {
                                //Specifiy key
                                RegistryKey registryKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computerName.ComputerInfo, RegistryView.Registry64);

                                var key = registryKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
                                if (key == null)
                                {

                                }
                                //Create objects for values
                                object lastUser = key.GetValue("LastLoggedOnUser");
                                object lastDisplayName = key.GetValue("LastLoggedOnDisplayName");

                                //Display information
                                Console.WriteLine(lastUser.ToString(), lastDisplayName.ToString());

                                //Write out results
                                File.AppendAllText(nekoFolder + "\\User Locations.txt", "Last user: " + lastUser.ToString() + Environment.NewLine + "Display Name: " + lastDisplayName.ToString() + Environment.NewLine
                                    + "Computer Name: " + computerName + Environment.NewLine);


                            }

                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }
                        }
                    }
                }
            }
        }

        //Method for remote registry tampering
        public static void RegModification(string nekoFolder, string domainURL, string Username, string Password)
        {
            //Confirm that user has appropriate creds and is able to query registry remotely. 
            Console.WriteLine("This process typically requires domain admin privileges and remote registry enabled. Conintue? Enter 'y' or 'n':");
            string userDecision = Console.ReadLine();
            while (userDecision != "y" && userDecision != "")
            {
                Console.WriteLine("Invalid Selection.\r\nThis process typically requires domain admin privileges and remote registry enabled. Conintue? Enter 'y' or 'n':");
            }
            if (userDecision == "y")
            {

                //Need to turn this into list from previous results
                Console.WriteLine("Enter '1' to use results from LDAP recon or '2' to specify target computer name:");
                userDecision = Console.ReadLine();
                while (userDecision != "1" && userDecision != "2")
                {
                    Console.WriteLine("Invalid selection.\r\nEnter '1' to use results from LDAP recon or '2' to specify target computer name:");
                    userDecision = Console.ReadLine();
                }

                if (userDecision == "2")
                {

                    //Declare computer name
                    string computerName = "";
                    //Get computer name
                    Console.WriteLine("Specify target computer name:");
                    computerName = Console.ReadLine();

                    //Get Hive name
                    Console.WriteLine("Specify hive:" +
                        "\r\n\r\n1: Local Machine" +
                        "\r\n\r\n2: Current User" +
                        "\r\n\r\n3: Users" +
                        "\r\n\r\n4: Classes Root");
                    string userChoice = Console.ReadLine();
                    //Loop to confirm correct input
                    while (userChoice != "1" && userChoice != "2" && userChoice != "3" && userChoice != "4")
                    {
                        Console.WriteLine("Invalid selection" +
                            "\r\n\r\nSpecify hive:" +
                        "\r\n\r\n1: LocalMachine" +
                        "\r\n\r\n2: CurrentUser" +
                        "\r\n\r\n3: Users" +
                        "\r\n\r\n4: ClassesRoot");
                    }

                    //Declare registryhive
                    RegistryHive registryHive = RegistryHive.LocalMachine;
                    if (userChoice == "1")
                    {
                        //Do nothing since it was set to default of LocalMachine   
                    }
                    //Set as CurrentUser hive
                    else if (userChoice == "2")
                    {
                        registryHive = RegistryHive.CurrentUser;
                    }
                    //Set as Users hive
                    else if (userChoice == "3")
                    {
                        registryHive = RegistryHive.Users;
                    }
                    //Set as ClassesRoot hive
                    else if (userChoice == "4")
                    {
                        registryHive = RegistryHive.ClassesRoot;
                    }

                    //Specify reg name
                    Console.WriteLine("Specify registry Name, e.g. 'DisableAntiSpyware':");
                    string name = Console.ReadLine();

                    //Get key choice
                    Console.WriteLine(@"Specify registry key, e.g. 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authenication\LogonUI':");
                    string regKey = @Console.ReadLine();

                    //Choose new value
                    Console.WriteLine("Specify new registry value, e.g. '0':");
                    string newValue = Console.ReadLine();

                    //Open remote key
                    try
                    {
                        //Open key
                        RegistryKey registryKey = RegistryKey.OpenRemoteBaseKey(registryHive, computerName, RegistryView.Registry64);

                        //open subkey
                        var key = registryKey.OpenSubKey(regKey);
                        if (key == null)
                        {

                        }
                        //Create objects for values
                        key.SetValue(name, newValue);

                        //Check that value was modified
                        object regValue = key.GetValue(name);

                        //Display information
                        Console.WriteLine(regValue.ToString());

                        //Write out results
                        File.AppendAllText(nekoFolder + "\\Registry modifications.txt", name + regValue.ToString() + Environment.NewLine + Environment.NewLine
                            + "Computer Name: " + computerName + Environment.NewLine);


                    }
                    catch (UnauthorizedAccessException e)
                    {
                        Console.WriteLine("Access Denied. Insuficient privileges.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
                else
                {
                    //ComputerName from list
                    //Access list class from LDAP recon, need to make this so user can specify their own list if they want.
                    Console.WriteLine("Have you run LDAP recon to generate machine name list? Enter 'y' or 'n'");
                    string userChoice = Console.ReadLine();
                    while (userChoice != "y" && userChoice != "n")
                    {
                        Console.WriteLine("Invalid selection. Have you run LDAP computer recon to generate machine name list? Enter 'y' or 'n'");
                    }
                    //Run ldap comnputer recon
                    if (userChoice == "n")
                    {
                        try
                        {
                            var computerList = Neko.ADComputer.GetADComputers(domainURL, Username, Password);
                            Console.WriteLine("\r\nFound computers:");

                            //Get unique file to prevent overwriting
                            string writePath = UniqueFileCheck.UniqueFile(nekoFolder + "\\LDAP Computer Recon.txt");

                            //Start stream writer for writing results
                            using (var writer = new StreamWriter(writePath, append: true))
                            {
                                foreach (var computer in computerList)
                                {
                                    Console.WriteLine(computer.ComputerInfo);
                                    Console.WriteLine(computer.LastLogon);
                                    Console.WriteLine(computer.ComputerType);

                                    //Write out results
                                    writer.WriteLine(Environment.NewLine + "Computer Name: " + computer.ComputerInfo + Environment.NewLine + "Last Logon: " + computer.LastLogon
                                        + Environment.NewLine + "Computer type " + computer.ComputerType);
                                    writer.Flush();

                                }
                            }
                        }
                        catch (UnauthorizedAccessException e)
                        {
                            Console.WriteLine("Access Denied. Insuficient privileges.");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                    }
                    //Run remote registry recon for all machines in list. 
                    else
                    {
                        var computerList = Neko.ADComputer.GetADComputers(domainURL, Username, Password);

                        foreach (var computerName in computerList)
                        {

                            //Get Hive name
                            Console.WriteLine("Specify hive:" +
                                "\r\n\r\n1: Local Machine" +
                                "\r\n\r\n2: Current User" +
                                "\r\n\r\n3: Users" +
                                "\r\n\r\n4: Classes Root");
                            userChoice = Console.ReadLine();
                            //Loop to confirm correct input
                            while (userChoice != "1" && userChoice != "2" && userChoice != "3" && userChoice != "4")
                            {
                                Console.WriteLine("Invalid selection" +
                                    "\r\n\r\nSpecify hive:" +
                                "\r\n\r\n1: LocalMachine" +
                                "\r\n\r\n2: CurrentUser" +
                                "\r\n\r\n3: Users" +
                                "\r\n\r\n4: ClassesRoot");
                            }

                            //Declare registryhive
                            RegistryHive registryHive = RegistryHive.LocalMachine;
                            if (userChoice == "1")
                            {
                                //Do nothing since it was set to default of LocalMachine   
                            }
                            //Set as CurrentUser hive
                            else if (userChoice == "2")
                            {
                                registryHive = RegistryHive.CurrentUser;
                            }
                            //Set as Users hive
                            else if (userChoice == "3")
                            {
                                registryHive = RegistryHive.Users;
                            }
                            //Set as ClassesRoot hive
                            else if (userChoice == "4")
                            {
                                registryHive = RegistryHive.ClassesRoot;
                            }

                            //Specify reg name
                            Console.WriteLine("Specify registry Name, e.g. 'DisableAntiSpyware':");
                            string name = Console.ReadLine();

                            //Get key choice
                            Console.WriteLine(@"Specify registry key, e.g. 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authenication\LogonUI':");
                            string regKey = @Console.ReadLine();

                            //Choose new value
                            Console.WriteLine("Specify new registry value, e.g. '0':");
                            string newValue = Console.ReadLine();

                            //Open remote key
                            try
                            {
                                //Open key
                                RegistryKey registryKey = RegistryKey.OpenRemoteBaseKey(registryHive, computerName.ComputerInfo, RegistryView.Registry64);

                                //open subkey
                                var key = registryKey.OpenSubKey(regKey);
                                if (key == null)
                                {

                                }
                                //Create objects for values
                                key.SetValue(name, newValue);

                                //Check that value was modified
                                object regValue = key.GetValue(name);

                                //Display information
                                Console.WriteLine(regValue.ToString());

                                //Write out results
                                File.AppendAllText(nekoFolder + "\\Registry modifications.txt", name + regValue.ToString() + Environment.NewLine + Environment.NewLine
                                    + "Computer Name: " + computerName + Environment.NewLine);
                            }
                            catch (UnauthorizedAccessException e)
                            {
                                Console.WriteLine("Access Denied. Insuficient privileges.");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }
                        }
                    }
                }
            }
        }
    }
}
