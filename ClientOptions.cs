namespace LightOAuth2
{
    public record ClientOptions(string AuthUrl, string TokenUrl, ushort RedirectPort, string ClientId, IAuthorizationProvider AuthorizationProvider) 
    {
        public string? Scope { get; init; }
        public ITokenCacheProvider? TokenCache { get; init; } 
    }

    public enum AuthMethod
    {
        ClientSecret = 0,
        CodeVerifier = 1
    }
}