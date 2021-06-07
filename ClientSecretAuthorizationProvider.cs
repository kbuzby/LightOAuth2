using System.Collections.Generic;

namespace LightOAuth2
{
    public class ClientSecretAuthorizationProvider : IAuthorizationProvider
    {
        private readonly string redirectUri;
        private readonly string clientId;
        private readonly string clientSecret;

        public ClientSecretAuthorizationProvider(string clientId, string clientSecret, string redirectUri)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.redirectUri = redirectUri;
        }

        public Dictionary<string, string?> GetAccessTokenParams(string authCode)
        {
            return new()
            {
                { "grant_type", "authorization_code" },
                { "code", authCode },
                { "redirect_uri", redirectUri },
                { "client_id", clientId },
                { "client_secret", clientSecret }
            };
        }

        public Dictionary<string, string?> GetAuthorizationParams(string? scope)
        {
            return new()
            {
                { "response_type", "code" },
                { "client_id", clientId },
                { "redirect_uri", redirectUri },
                { "scope", scope }
            };
        }
    }
}