namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;

    internal sealed class OpenCifsServerAccountRegistry
    {
        private readonly Dictionary<string, OpenCifsServerAccount> _Accounts = new Dictionary<string, OpenCifsServerAccount>(StringComparer.OrdinalIgnoreCase);

        internal Dictionary<string, OpenCifsServerAccount> Accounts
        {
            get
            {
                return _Accounts;
            }
        }

        public void RegisterAccount(OpenCifsServerAccount account)
        {
            if (account == null)
            {
                throw new ArgumentNullException(nameof(account), "Account cannot be null.");
            }

            OpenCifsServerAccount clonedAccount = new OpenCifsServerAccount
            {
                UserName = account.UserName,
                UserDomain = account.UserDomain,
                Password = account.Password
            };
            _Accounts[OpenCifsServerSessionSetupSupport.GetAccountKey(clonedAccount.UserName, clonedAccount.UserDomain)] = clonedAccount;
        }
    }
}
