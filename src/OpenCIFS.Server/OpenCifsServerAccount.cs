namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// In-memory account definition for the current OpenCIFS session-setup slice.
    /// </summary>
    public sealed class OpenCifsServerAccount
    {
        /// <summary>
        /// User name.
        /// </summary>
        public string UserName
        {
            get
            {
                return _UserName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(UserName), "UserName cannot be null or whitespace.");
                }

                _UserName = value;
            }
        }

        /// <summary>
        /// Optional user domain.
        /// </summary>
        public string UserDomain
        {
            get
            {
                return _UserDomain;
            }
            set
            {
                _UserDomain = value ?? throw new ArgumentNullException(nameof(UserDomain), "UserDomain cannot be null.");
            }
        }

        /// <summary>
        /// Clear-text password used for NTLMv2 verification in the current in-memory host.
        /// </summary>
        public string Password
        {
            get
            {
                return _Password;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(Password), "Password cannot be null or whitespace.");
                }

                _Password = value;
            }
        }

        private string _UserName = string.Empty;
        private string _UserDomain = string.Empty;
        private string _Password = string.Empty;
    }
}
