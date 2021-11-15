using System;
using System.IO;
using System.Collections;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Configuration;
using System.Net;
using System.Net.NetworkInformation;
using sySecurity;

namespace syADS
{
    public interface IsyADS
    {
        bool IsAuthenticated(string sUserName, string sPassword, string sDefaultPath, string sLogPath = "");
        string ADS_CheckIn(string sUserName, string sRequiredPropertie, string sDefaultPath, string sLogPath = "");
        string ADS_GetInfo(string sUserName, string sRequiredPropertie, string sDefaultPath, string sLogPath = "");
        string GetTimeRemainingUntilPasswordExpiration(string sUserName, string sDefaultPath, string sLogPath = ""); //my comments for testing GIT

    }


    public class ADMethodsAccountManagement : IsyADS
    {

        #region Variables

        private string sDomain = "SYNEL";
        private string sDefaultOU = "ou=Yoqneam,ou=Synel,dc=SYNEL-COMPANY,dc=LTD";
        private string sDefaultRootOU = "ou=Yoqneam,ou=Synel,dc=SYNEL-COMPANY,dc=LTD";
        private string sServiceUser = @"";
        private string sServicePassword = "";

        #endregion


        #region Delphi Migration Methods

        public string AssemblyDirectory
        {
            get
            {
                string codeBase = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
                UriBuilder uri = new UriBuilder(codeBase);
                string path = Uri.UnescapeDataString(uri.Path);
                return Path.GetDirectoryName(path);
            }
        }


        public bool WriteFile(string FileName, string s, bool NewLine, bool AddTime)
        {
            if (String.IsNullOrEmpty(FileName))
                return false;

            FileName = FileName + "\\syADS.dat";

            bool suc = true;
            try
            {
                StreamWriter sw = File.AppendText(FileName);
                if (AddTime == true)
                {
                    s = DateTime.Now.ToString("yyyy'-'MM'-'dd' 'HH':'mm':'ss'.'fff' '")
                           + "[" + System.Threading.Thread.CurrentThread.ManagedThreadId.ToString("X8") + "] " + s;
                }
                if (NewLine == true)
                    sw.WriteLine(s);
                else
                    sw.Write(s);

                sw.Close();
            }
            catch
            {
                suc = false;
            }
            return suc;
        }



        /// <summary>
        /// Validates the username and password of a given user
        /// </summary>
        /// <param name="sUserName">The username to validate</param>
        /// <param name="sPassword">The password of the username to validate</param>
        /// <returns>Returns True of user is valid</returns>
        public bool IsAuthenticated(string sUserName, string sPassword, string sDefaultPath, string sLogPath = "")
        {
            SYPassword SY = new SYPassword();            

            bool authenticated = false;

            WriteFile(sLogPath, "Start IsAuthenticationed", true, true);
            WriteFile(sLogPath, "User: " + sUserName, true, true);
            WriteFile(sLogPath, "Pass: " + SY.AES_EncodePassword( sPassword ) , true, true);
            WriteFile(sLogPath, "Path: " + sDefaultPath, true, true);

            try
            {
                DirectoryEntry entry = new DirectoryEntry(sDefaultPath, sUserName, sPassword);
                object nativeObject = entry.NativeObject;
                authenticated = true;
            }
            catch (DirectoryServicesCOMException cex)
            {
                //not authenticated; reason why is in cex
                WriteFile(sLogPath, "Not authenticated !! - " + cex.Message, true, true);

            }
            catch (Exception ex)
            {
                //not authenticated due to some other exception [this is optional]
                WriteFile(sLogPath, "Not authenticated due to some other exception !! - " + ex.Message, true, true);
            }
            return authenticated;
        }

        /// <summary>
        /// Get value from AD of a given user
        /// </summary>
        /// <param name="sUserName">The username to validate</param>
        /// <param name="sRequiredPropertie">The field name in AD</param>
        /// <param name="sDefaultPath">The path connecting to AD</param>
        /// <returns>Returns user field value</returns>
        public string ADS_CheckIn(string sUserName, string sRequiredPropertie, string sDefaultPath, string sLogPath = "")
        {
            string ret = "-1";

            WriteFile(sLogPath, "Start ADS_CheckIn", true, true);
            WriteFile(sLogPath, "User: " + sUserName, true, true);
            WriteFile(sLogPath, "Prop: " + sRequiredPropertie, true, true);
            WriteFile(sLogPath, "Path: " + sDefaultPath, true, true);

            try
            {
                DirectoryEntry ldapConnection = new DirectoryEntry(sDefaultPath);
                ldapConnection.AuthenticationType = AuthenticationTypes.Secure;


                DirectorySearcher search = new DirectorySearcher(ldapConnection);

                //search.Filter = "(cn=" + sUserName + ")";
                search.Filter = "(samaccountname=" + sUserName + ")";


                WriteFile(sLogPath, "Search.Filter " + search.Filter, true, true);

                // create an array of properties that we would like and  
                // add them to the search object  
                string[] requiredProperties = new string[] { sRequiredPropertie };

                foreach (String property in requiredProperties)
                    search.PropertiesToLoad.Add(property);

                SearchResult result = search.FindOne();

                if (result != null)
                {
                    WriteFile(sLogPath, "Search result not null", true, true);

                    foreach (String property in requiredProperties)
                        foreach (Object myCollection in result.Properties[property])
                            ret = myCollection.ToString();

                }
            }
            catch (Exception ex)
            {
                WriteFile(sLogPath, "Error in ADS_CheckIn !! - " + ex.Message, true, true);
            };

            WriteFile(sLogPath, "Finish ADS_CheckIn return - " + ret, true, true);
            return ret;
        }


        /// <summary>
        /// Get value from AD of a CN name
        /// </summary>
        /// <param name="sUserName">The username to validate</param>
        /// <param name="sRequiredPropertie">The field name in AD</param>
        /// <param name="sDefaultPath">The path connecting to AD</param>
        /// <returns>Returns user field value</returns>
        public string ADS_GetInfo(string sUserName, string sRequiredPropertie, string sDefaultPath, string sLogPath = "")
        {
            string ret = "-1";

            WriteFile(sLogPath, "Start ADS_GetInfo", true, true);
            WriteFile(sLogPath, "User: " + sUserName, true, true);
            WriteFile(sLogPath, "Prop: " + sRequiredPropertie, true, true);
            WriteFile(sLogPath, "Path: " + sDefaultPath, true, true);

            try
            {
                DirectoryEntry ldapConnection = new DirectoryEntry(sDefaultPath);
                ldapConnection.AuthenticationType = AuthenticationTypes.Secure;


                DirectorySearcher search = new DirectorySearcher(ldapConnection);

                search.Filter = "(cn=" + sUserName + ")";
                //search.Filter = "(samaccountname=" + sUserName + ")";


                WriteFile(sLogPath, "Search.Filter " + search.Filter, true, true);

                // create an array of properties that we would like and  
                // add them to the search object  
                string[] requiredProperties = new string[] { sRequiredPropertie };

                foreach (String property in requiredProperties)
                    search.PropertiesToLoad.Add(property);

                SearchResult result = search.FindOne();

                if (result != null)
                {
                    WriteFile(sLogPath, "Search result not null", true, true);

                    foreach (String property in requiredProperties)
                        foreach (Object myCollection in result.Properties[property])
                            ret = myCollection.ToString();

                }
            }
            catch (Exception ex)
            {
                WriteFile(sLogPath, "Error in ADS_GetInfo !! - " + ex.Message, true, true);
            };

            WriteFile(sLogPath, "Finish ADS_GetInfo return - " + ret, true, true);
            return ret;
        }


        public string GetTimeRemainingUntilPasswordExpiration(string sUserName, string sDefaultPath, string sLogPath = "")
        {

            string ret = "-1";
            string domainAndUsername = string.Empty;
            domainAndUsername = sDefaultPath + "/cn=" + sUserName +"\" ";  

            WriteFile(sLogPath, "Start GetTimeRemainingUntilPasswordExpiration", true, true);
            WriteFile(sLogPath, "User: " + sUserName, true, true);           
            WriteFile(sLogPath, "Path: " + sDefaultPath, true, true);


            try
            {
                DirectoryEntry ldapConnection = new DirectoryEntry(sDefaultPath);
                ldapConnection.AuthenticationType = AuthenticationTypes.Secure;


                DirectorySearcher search = new DirectorySearcher(ldapConnection);

                SearchResultCollection results;
                string filter = "maxPwdAge=*";
                search.Filter = filter;

                results = search.FindAll();
                long maxDays = 0;

                if (results.Count >= 1)
                {
                    Int64 maxPwdAge = (Int64)results[0].Properties["maxPwdAge"][0];
                    maxDays = maxPwdAge / -864000000000;
                }


                DirectoryEntry ldapConnection1 = new DirectoryEntry(sDefaultPath);
                ldapConnection1.AuthenticationType = AuthenticationTypes.Secure;


                DirectorySearcher search1 = new DirectorySearcher(ldapConnection1);

                //search.Filter = "(cn=" + sUserName + ")";
                search1.Filter = "(samaccountname=" + sUserName + ")";


               

                // create an array of properties that we would like and  
                // add them to the search object  
                string[] requiredProperties = new string[] { "PasswordExpirationDate" };

                foreach (String property in requiredProperties)
                    search1.PropertiesToLoad.Add(property);

                SearchResult result1 = search.FindOne();

                if (result1 != null)
                {
                    WriteFile(sLogPath, "Search result not null", true, true);

                    foreach (String property in requiredProperties)
                        foreach (Object myCollection in result1.Properties[property])
                            ret = myCollection.ToString();

                }



/*                DirectoryEntry ldapConnection1 = new DirectoryEntry(sDefaultPath, "sharonc", "S025252800&", ldapConnection.AuthenticationType);
                //DirectoryEntry ldapConnection1 = new DirectoryEntry(domainAndUsername, "sharonc", "S025252800&", ldapConnection.AuthenticationType);
                //ldapConnection1.AuthenticationType = AuthenticationTypes.Secure;


                DirectorySearcher search1 = new DirectorySearcher(ldapConnection1);


               // DirectoryEntry entryUser = new DirectoryEntry(
               //                         domainAndUsername);
               // search = new DirectorySearcher(entryUser);

                results = search1.FindAll();
                long daysLeft = 0;
                if (results.Count >= 1)
                {
                    var lastChanged = results[0].Properties["pwdLastSet"][0];
                    daysLeft = maxDays - DateTime.Today.Subtract(
                            DateTime.FromFileTime((long)lastChanged)).Days;
                }

                ret = daysLeft.ToString();
*/

            }
            catch (Exception ex)
            {
                WriteFile(sLogPath, "Error in GetTimeRemainingUntilPasswordExpiration !! - " + ex.Message, true, true);
            };

            WriteFile(sLogPath, "You must change your password within {0} days" + ret, true, true);
            WriteFile(sLogPath, "Finish GetTimeRemainingUntilPasswordExpiration return - " + ret, true, true);
            return ret;










/*

            
            using (var userEntry = new System.DirectoryServices.DirectoryEntry(string.Format("LDAP://{0}/{1},user", domain, userName)))
            {
                var maxPasswordAge = (int)userEntry.Properties.Cast<System.DirectoryServices.PropertyValueCollection>().First(p => p.PropertyName == "MaxPasswordAge").Value;
                var passwordAge = (int)userEntry.Properties.Cast<System.DirectoryServices.PropertyValueCollection>().First(p => p.PropertyName == "PasswordAge").Value;
                return TimeSpan.FromSeconds(maxPasswordAge) - TimeSpan.FromSeconds(passwordAge);
            }
 */
             
        }


        #endregion

        #region Validate Methods

        /// <summary>
        /// Validates the username and password of a given user
        /// </summary>
        /// <param name="sUserName">The username to validate</param>
        /// <param name="sPassword">The password of the username to validate</param>
        /// <returns>Returns True of user is valid</returns>
        public bool ValidateCredentials(string sUserName, string sPassword)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();
            return oPrincipalContext.ValidateCredentials(sUserName, sPassword);
        }

        /// <summary>
        /// Checks if the User Account is Expired
        /// </summary>
        /// <param name="sUserName">The username to check</param>
        /// <returns>Returns true if Expired</returns>
        public bool IsUserExpired(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            if (oUserPrincipal.AccountExpirationDate != null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// Checks if user exists on AD
        /// </summary>
        /// <param name="sUserName">The username to check</param>
        /// <returns>Returns true if username Exists</returns>
        public bool IsUserExisiting(string sUserName)
        {
            if (GetUser(sUserName) == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// Checks if user account is locked
        /// </summary>
        /// <param name="sUserName">The username to check</param>
        /// <returns>Returns true of Account is locked</returns>
        public bool IsAccountLocked(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            return oUserPrincipal.IsAccountLockedOut();
        }
        #endregion

        #region Search Methods

        /// <summary>
        /// Gets a certain user on Active Directory
        /// </summary>
        /// <param name="sUserName">The username to get</param>
        /// <returns>Returns the UserPrincipal Object</returns>
        public UserPrincipal GetUser(string sUserName)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();

            UserPrincipal oUserPrincipal =
               UserPrincipal.FindByIdentity(oPrincipalContext, sUserName);
            return oUserPrincipal;
        }

        /// <summary>
        /// Gets a certain group on Active Directory
        /// </summary>
        /// <param name="sGroupName">The group to get</param>
        /// <returns>Returns the GroupPrincipal Object</returns>
        public GroupPrincipal GetGroup(string sGroupName)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();

            GroupPrincipal oGroupPrincipal =
               GroupPrincipal.FindByIdentity(oPrincipalContext, sGroupName);
            return oGroupPrincipal;
        }

        #endregion

        #region User Account Methods

        /// <summary>
        /// Sets the user password
        /// </summary>
        /// <param name="sUserName">The username to set</param>
        /// <param name="sNewPassword">The new password to use</param>
        /// <param name="sMessage">Any output messages</param>
        public void SetUserPassword(string sUserName, string sNewPassword, out string sMessage)
        {
            try
            {
                UserPrincipal oUserPrincipal = GetUser(sUserName);
                oUserPrincipal.SetPassword(sNewPassword);
                sMessage = "";
            }
            catch (Exception ex)
            {
                sMessage = ex.Message;
            }
        }

        /// <summary>
        /// Enables a disabled user account
        /// </summary>
        /// <param name="sUserName">The username to enable</param>
        public void EnableUserAccount(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            oUserPrincipal.Enabled = true;
            oUserPrincipal.Save();
        }

        /// <summary>
        /// Force disabling of a user account
        /// </summary>
        /// <param name="sUserName">The username to disable</param>
        public void DisableUserAccount(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            oUserPrincipal.Enabled = false;
            oUserPrincipal.Save();
        }

        /// <summary>
        /// Force expire password of a user
        /// </summary>
        /// <param name="sUserName">The username to expire the password</param>
        public void ExpireUserPassword(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            oUserPrincipal.ExpirePasswordNow();
            oUserPrincipal.Save();
        }

        /// <summary>
        /// Unlocks a locked user account
        /// </summary>
        /// <param name="sUserName">The username to unlock</param>
        public void UnlockUserAccount(string sUserName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            oUserPrincipal.UnlockAccount();
            oUserPrincipal.Save();
        }

        /// <summary>
        /// Creates a new user on Active Directory
        /// </summary>
        /// <param name="sOU">The OU location you want to save your user</param>
        /// <param name="sUserName">The username of the new user</param>
        /// <param name="sPassword">The password of the new user</param>
        /// <param name="sGivenName">The given name of the new user</param>
        /// <param name="sSurname">The surname of the new user</param>
        /// <returns>returns the UserPrincipal object</returns>
        public UserPrincipal CreateNewUser(string sOU,
           string sUserName, string sPassword, string sGivenName, string sSurname)
        {
            if (!IsUserExisiting(sUserName))
            {
                PrincipalContext oPrincipalContext = GetPrincipalContext(sOU);

                UserPrincipal oUserPrincipal = new UserPrincipal
                   (oPrincipalContext, sUserName, sPassword, true /*Enabled or not*/);

                //User Log on Name
                oUserPrincipal.UserPrincipalName = sUserName;
                oUserPrincipal.GivenName = sGivenName;
                oUserPrincipal.Surname = sSurname;
                oUserPrincipal.Save();

                return oUserPrincipal;
            }
            else
            {
                return GetUser(sUserName);
            }
        }

        /// <summary>
        /// Deletes a user in Active Directory
        /// </summary>
        /// <param name="sUserName">The username you want to delete</param>
        /// <returns>Returns true if successfully deleted</returns>
        public bool DeleteUser(string sUserName)
        {
            try
            {
                UserPrincipal oUserPrincipal = GetUser(sUserName);

                oUserPrincipal.Delete();
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Group Methods

        /// <summary>
        /// Creates a new group in Active Directory
        /// </summary>
        /// <param name="sOU">The OU location you want to save your new Group</param>
        /// <param name="sGroupName">The name of the new group</param>
        /// <param name="sDescription">The description of the new group</param>
        /// <param name="oGroupScope">The scope of the new group</param>
        /// <param name="bSecurityGroup">True is you want this group 
        /// to be a security group, false if you want this as a distribution group</param>
        /// <returns>Returns the GroupPrincipal object</returns>
        public GroupPrincipal CreateNewGroup(string sOU, string sGroupName,
           string sDescription, GroupScope oGroupScope, bool bSecurityGroup)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext(sOU);

            GroupPrincipal oGroupPrincipal = new GroupPrincipal(oPrincipalContext, sGroupName);
            oGroupPrincipal.Description = sDescription;
            oGroupPrincipal.GroupScope = oGroupScope;
            oGroupPrincipal.IsSecurityGroup = bSecurityGroup;
            oGroupPrincipal.Save();

            return oGroupPrincipal;
        }

        /// <summary>
        /// Adds the user for a given group
        /// </summary>
        /// <param name="sUserName">The user you want to add to a group</param>
        /// <param name="sGroupName">The group you want the user to be added in</param>
        /// <returns>Returns true if successful</returns>
        public bool AddUserToGroup(string sUserName, string sGroupName)
        {
            try
            {
                UserPrincipal oUserPrincipal = GetUser(sUserName);
                GroupPrincipal oGroupPrincipal = GetGroup(sGroupName);
                if (oUserPrincipal == null || oGroupPrincipal == null)
                {
                    if (!IsUserGroupMember(sUserName, sGroupName))
                    {
                        oGroupPrincipal.Members.Add(oUserPrincipal);
                        oGroupPrincipal.Save();
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Removes user from a given group
        /// </summary>
        /// <param name="sUserName">The user you want to remove from a group</param>
        /// <param name="sGroupName">The group you want the user to be removed from</param>
        /// <returns>Returns true if successful</returns>
        public bool RemoveUserFromGroup(string sUserName, string sGroupName)
        {
            try
            {
                UserPrincipal oUserPrincipal = GetUser(sUserName);
                GroupPrincipal oGroupPrincipal = GetGroup(sGroupName);
                if (oUserPrincipal == null || oGroupPrincipal == null)
                {
                    if (IsUserGroupMember(sUserName, sGroupName))
                    {
                        oGroupPrincipal.Members.Remove(oUserPrincipal);
                        oGroupPrincipal.Save();
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if user is a member of a given group
        /// </summary>
        /// <param name="sUserName">The user you want to validate</param>
        /// <param name="sGroupName">The group you want to check the 
        /// membership of the user</param>
        /// <returns>Returns true if user is a group member</returns>
        public bool IsUserGroupMember(string sUserName, string sGroupName)
        {
            UserPrincipal oUserPrincipal = GetUser(sUserName);
            GroupPrincipal oGroupPrincipal = GetGroup(sGroupName);

            if (oUserPrincipal == null || oGroupPrincipal == null)
            {
                return oGroupPrincipal.Members.Contains(oUserPrincipal);
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Gets a list of the users group memberships
        /// </summary>
        /// <param name="sUserName">The user you want to get the group memberships</param>
        /// <returns>Returns an arraylist of group memberships</returns>
        public ArrayList GetUserGroups(string sUserName)
        {
            ArrayList myItems = new ArrayList();
            UserPrincipal oUserPrincipal = GetUser(sUserName);

            PrincipalSearchResult<Principal> oPrincipalSearchResult = oUserPrincipal.GetGroups();

            foreach (Principal oResult in oPrincipalSearchResult)
            {
                myItems.Add(oResult.Name);
            }
            return myItems;
        }

        /// <summary>
        /// Gets a list of the users authorization groups
        /// </summary>
        /// <param name="sUserName">The user you want to get authorization groups</param>
        /// <returns>Returns an arraylist of group authorization memberships</returns>
        public ArrayList GetUserAuthorizationGroups(string sUserName)
        {
            ArrayList myItems = new ArrayList();
            UserPrincipal oUserPrincipal = GetUser(sUserName);

            PrincipalSearchResult<Principal> oPrincipalSearchResult =
                       oUserPrincipal.GetAuthorizationGroups();

            foreach (Principal oResult in oPrincipalSearchResult)
            {
                myItems.Add(oResult.Name);
            }
            return myItems;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Gets the base principal context
        /// </summary>
        /// <returns>Returns the PrincipalContext object</returns>
        public PrincipalContext GetPrincipalContext()
        {
            PrincipalContext oPrincipalContext = new PrincipalContext
               (ContextType.Domain, sDomain, sDefaultOU, ContextOptions.SimpleBind,
               sServiceUser, sServicePassword);
            return oPrincipalContext;
        }

        /// <summary>
        /// Gets the principal context on specified OU
        /// </summary>
        /// <param name="sOU">The OU you want your Principal Context to run on</param>
        /// <returns>Returns the PrincipalContext object</returns>
        public PrincipalContext GetPrincipalContext(string sOU)
        {
            PrincipalContext oPrincipalContext =
               new PrincipalContext(ContextType.Domain, sDomain, sOU,
               ContextOptions.SimpleBind, sServiceUser, sServicePassword);
            return oPrincipalContext;
        }

        #endregion

    }

}
