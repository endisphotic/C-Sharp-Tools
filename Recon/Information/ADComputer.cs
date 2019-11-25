using System;
using System.Collections.Generic;
using System.DirectoryServices;


namespace Neko
{
    public class ADComputer
    {
        /// <summary>
        /// Property of last logon
        /// </summary>
        public const string lastLogonProperty = "lastLogon";

        //Gets or sets last logon
        public string LastLogon { get; set; }

        /// <summary>
        /// User name property
        /// </summary>
        public const string distinguishedNameProperty = "distinguishedName";

        /// <summary>
        /// Gets or sets user name
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets Computer type
        /// </summary>
        public string ComputerType { get; set; }

        /// <summary>
        /// Property of Computer Name
        /// </summary>
        public const string computerName = "location";

        /// <summary>
        /// Gets or sets the computer
        /// </summary>
        public string ComputerInfo { get; set; }

        public static List<ADComputer> GetADComputers(string domainURL, string Username, string Password)
        {
            // Create new list
            List<ADComputer> computers = new List<ADComputer>();

            // Create new DE
            DirectoryEntry entry = new DirectoryEntry("LDAP://" + domainURL);

            // Set user and pass
            entry.Username = Username;
            entry.Password = Password;

            // Create new searcher
            DirectorySearcher mySearch = new DirectorySearcher(entry);
            // Limit to only computers
            mySearch.Filter = "(objectClass=computer)";

            // Add properties to load for last logon and last user name
            mySearch.PropertiesToLoad.AddRange(new[] { lastLogonProperty, distinguishedNameProperty });

            foreach (SearchResult results in mySearch.FindAll())
            {
                var computer = new ADComputer();

                string ComputerName = results.GetDirectoryEntry().Name;
                // Remove CN from results
                if (ComputerName.StartsWith("CN=")) ComputerName = ComputerName.Remove(0, "CN=".Length); computer.ComputerInfo = ComputerName.ToString();

                // Gets information about type of computer
                if (results.Properties[distinguishedNameProperty].Count > 0) computer.ComputerType = results.Properties[distinguishedNameProperty][0].ToString();

                // Checks last logon
                if (results.Properties[lastLogonProperty].Count > 0) computer.LastLogon = Convert.ToString(DateTime.FromFileTime((long)results.Properties[lastLogonProperty][0]));

                // Add to list
                computers.Add(computer);
            }
            return computers;
        }
    }
}
