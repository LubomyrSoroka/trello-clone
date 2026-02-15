public class SecretsService
{
    public string JwtSecret { get; }

    public string EmailPassword { get; }

    public string PersonalEmail { get; }
    public string ClientUrl { get; }

    public SecretsService(string jwtSecret, string emailPassword, string email, string clientUrl)
    {
        JwtSecret = jwtSecret;
        EmailPassword = emailPassword;
        PersonalEmail = email;
        ClientUrl = clientUrl;
    }
}
