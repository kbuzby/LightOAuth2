using System;

namespace LightOAuth2
{
    public class TokenInfoUpdatedEventArgs : EventArgs
    {
        public TokenInfoUpdatedEventArgs(TokenInfo? tokenInfo)
            => TokenInfo = tokenInfo;

        public TokenInfo? TokenInfo { get; init; }
    }
}