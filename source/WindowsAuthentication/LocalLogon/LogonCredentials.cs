namespace IdentityServer.WindowsAuthentication.LocalLogon
{
    public class LogonCredentials
    {
        public LogonCredentials(string user, string password, string defaultDomain = null)
        {
            if (user.IndexOf('@') > 0)
            {
                string[] parts = user.Split('@');
                User = parts[0];
                Domain = parts[1];
            }
            else if (user.IndexOf('\\') > 0)
            {
                string[] parts = user.Split('\\');
                User = parts[1];
                Domain = parts[0];
            }
            else
            {
                User = user;
                Domain = defaultDomain;
            }
            Password = password;
        }

        public string User { get; }
        public string Domain { get; }
        public string Password { get; }
    }
}
