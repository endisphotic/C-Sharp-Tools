using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;

namespace Neko
{
    class ADUser
    {
        /// <summary>
        /// Property of sAM account name
        /// </summary>
        public const string SamAccountNameProperty = "sAMAccountName";

        /// <summary>
        /// Property of name CN
        /// </summary>
        public const string CanonicalNameProperty = "CN";

        /// <summary>
        /// Property of SID
        /// </summary>
        public const string SidProperty = "objectSid";

        /// <summary>
        /// Property for First Name
        /// </summary>
        public const string FirstNameProperty = "givenName";

        /// <summary>
        /// Property for last name
        /// </summary>
        public const string LastNameProperty = "sn";

        /// <summary>
        /// Property to get AD group membership
        /// </summary>
        public const string MemberOfProperty = "memberOf";

        /// <summary>
        /// Property for direct reports
        /// </summary>
        public const string DirectReportsProperty = "directReports";

        /// <summary>
        /// Property for logoff info
        /// </summary>
        public const string LastLogoffProperty = "lastLogoff";

        /// <summary>
        /// Property for street address info
        /// </summary>
        public const string StreetAddressProperty = "streesAddress";

        /// <summary>
        /// Property for last logon info
        /// </summary>
        public const string LastLogonProperty = "lastLogon";

        /// <summary>
        /// Property for admin count
        /// </summary>
        public const string AdminCountProperty = "adminCount";

        /// <summary>
        /// Gets or sets admin count
        /// </summary>
        public string AdminCount { get; set; }

        /// <summary>
        /// Gets or set last logon
        /// </summary>
        public string LastLogon { get; set; }

        /// <summary>
        /// Gets or sets street address info
        /// </summary>
        public string StreetAddress { get; set; }

        /// <summary>
        /// Gets or sets last logoff info
        /// </summary>
        public string LastLogoff { get; set; }

        /// <summary>
        /// Gets or set direct reports info
        /// </summary>
        public string DirectReports { get; set; }

        /// <summary>
        /// Gets or sets member of
        /// </summary>
        public string MemberOf { get; set; }

        /// <summary>
        /// Gets or sets last name
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        /// Gets for sets first name
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the SID of the user
        /// </summary>
        public string SID { get; set; }

        /// <summary>
        /// Gets or sets the CN of the user
        /// </summary>
        public string CN { get; set; }

        /// <summary>
        /// Gets or sets the sAM Account name
        /// </summary>
        public string SamAccountName { get; set; }

        //public static List<string> myList = new List<string>();
        /// <summary>
        /// Gets users of domain
        /// </summary>
        /// <param name="domainURL"></param>
        /// <returns></returns>
        public static List<ADUser> GetUsers(string domainURL, string UserName, string Password)
        {
            List<ADUser> users = new List<ADUser>();

            //using (DirectoryEntry searchRoot = new DirectoryEntry(domainURL))
            DirectoryEntry searchRoot = new DirectoryEntry(domainURL);

            // Set user and password
            searchRoot.Username = UserName;
            searchRoot.Password = Password;

            using (DirectorySearcher directorySearcher = new DirectorySearcher(searchRoot))
            {
                // Set filter
                directorySearcher.Filter = "(&(objectCategory=person)(objectClass=user))";

                // Set properties to load based on above strings
                directorySearcher.PropertiesToLoad.Add(CanonicalNameProperty);
                directorySearcher.PropertiesToLoad.Add(SamAccountNameProperty);
                directorySearcher.PropertiesToLoad.Add(SidProperty);
                directorySearcher.PropertiesToLoad.Add(FirstNameProperty);
                directorySearcher.PropertiesToLoad.Add(LastNameProperty);
                directorySearcher.PropertiesToLoad.Add(MemberOfProperty);
                directorySearcher.PropertiesToLoad.Add(DirectReportsProperty);
                directorySearcher.PropertiesToLoad.Add(StreetAddressProperty);
                directorySearcher.PropertiesToLoad.Add(LastLogoffProperty);
                directorySearcher.PropertiesToLoad.Add(LastLogonProperty);
                directorySearcher.PropertiesToLoad.Add(AdminCountProperty);

                using (SearchResultCollection searchResultCollection = directorySearcher.FindAll())
                {
                    foreach (SearchResult searchResult in searchResultCollection)
                    {
                        // Create new AD user instance
                        var user = new ADUser();

                        // Set CN if avail
                        if (searchResult.Properties[CanonicalNameProperty].Count > 0) user.CN = searchResult.Properties[CanonicalNameProperty][0].ToString();

                        // Set samaccount if available
                        if (searchResult.Properties[SamAccountNameProperty].Count > 0) user.SamAccountName = searchResult.Properties[SamAccountNameProperty][0].ToString();

                        // Set first name info
                        if (searchResult.Properties[FirstNameProperty].Count > 0) user.FirstName = searchResult.Properties[FirstNameProperty][0].ToString();

                        // Sets last name info
                        if (searchResult.Properties[LastNameProperty].Count > 0) user.LastName = searchResult.Properties[LastNameProperty][0].ToString();

                        // Sets member of info
                        if (searchResult.Properties[MemberOfProperty].Count > 0) user.MemberOf = searchResult.Properties[MemberOfProperty][0].ToString();

                        // Sets direct reports info if there
                        if (searchResult.Properties[DirectReportsProperty].Count > 0) user.DirectReports = searchResult.Properties[DirectReportsProperty][0].ToString();

                        //Sets street address info
                        if (searchResult.Properties[StreetAddressProperty].Count > 0) user.StreetAddress = searchResult.Properties[StreetAddressProperty][0].ToString();

                        // Sets last logoff info
                        if (searchResult.Properties[LastLogoffProperty].Count > 0) user.LastLogoff = searchResult.Properties[LastLogoffProperty][0].ToString();

                        // Sets last logon info
                        if (searchResult.Properties[LastLogonProperty].Count > 0) user.LastLogon = Convert.ToString(DateTime.FromFileTime((long)searchResult.Properties[LastLogonProperty][0]));

                        // Gets admin count
                        if (searchResult.Properties[AdminCountProperty].Count > 0) user.AdminCount = searchResult.Properties[AdminCountProperty][0].ToString();

                        // Get SID if available
                        if (searchResult.Properties[SidProperty].Count > 0) user.SID = (new SecurityIdentifier((byte[])searchResult.Properties[SidProperty][0], 0).Value);

                        // Add use to users list
                        users.Add(user);
                    }
                }
            }
            return users;
        }
    }
}
