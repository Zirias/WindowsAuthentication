using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace IdentityServer.WindowsAuthentication.LocalLogon
{
    public static class WindowsLogon
    {
        [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LogonUser(
            [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
            [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
            [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int
           SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

        const int LOGON32_LOGON_NETWORK = 3;
        const int LOGON32_PROVIDER_DEFAULT = 0;

        /// <summary>
        /// Perform a local windows logon
        /// </summary>
        /// <param name="cred">The credentials used for the logon</param>
        /// <returns>A WindowsIdentity, this is the anonymous identity on logon failure</returns>
        public static WindowsIdentity Logon(LogonCredentials cred)
        {
            IntPtr hToken;
            IntPtr hTokenDuplicate;
            if (LogonUser(cred.User, cred.Domain, cred.Password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out hToken))
            {
                if (DuplicateToken(hToken, 2, out hTokenDuplicate))
                {
                    return new WindowsIdentity(hTokenDuplicate);
                }
            }

            return WindowsIdentity.GetAnonymous();
        }
    }
}
