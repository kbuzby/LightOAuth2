using System.Collections.Generic;

namespace LightOAuth2
{
    public interface IAuthorizationProvider
    {
        Dictionary<string, string?> GetAuthorizationParams(string? scope);

        Dictionary<string, string?> GetAccessTokenParams(string authCode);
    }
}