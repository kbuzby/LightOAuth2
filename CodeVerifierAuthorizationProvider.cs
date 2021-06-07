using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace LightOAuth2
{
    public class CodeVerifierAuthorizationProvider : IAuthorizationProvider
    {
        private static readonly RandomNumberGenerator rng;
        private static readonly SHA256 sha256;
        private readonly string clientId;
        private readonly string redirectUri;
        private byte[]? code_verifier;

        static CodeVerifierAuthorizationProvider()
        {
            rng = RandomNumberGenerator.Create();
            sha256 = SHA256.Create();
        }

        public CodeVerifierAuthorizationProvider(string clientId, string redirectUri)
        {
            this.clientId = clientId;
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
                { "code_verifier", Encoding.UTF8.GetString(code_verifier!) }
            };
        }

        public Dictionary<string, string?> GetAuthorizationParams(string? scope)
        {
            static byte[] GenerateCode()
            {
                var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYXZ1234567890-._~";
                var charLen = chars.Length;
                var buffer = new byte[48];
                rng.GetBytes(buffer);
                for (short i = 0; i < 48; i++)
                {
                    var pos = buffer[i] % charLen;
                    buffer[i] = (byte)chars[pos];
                }
                return buffer;
            };

            static string HashAndEncode(byte[] buffer)
                => System.Convert.ToBase64String(sha256.ComputeHash(buffer))
                    .Replace('/', '_')
                    .Replace('+', '-')
                    .Replace("=", "");

            code_verifier = GenerateCode();
            var s = Encoding.UTF8.GetString(code_verifier);

            return new()
            {
                { "client_id", clientId },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
                { "code_challenge_method", "S256" },
                { "code_challenge", HashAndEncode(code_verifier!) },
                { "scope", scope }
            };
        }
    }
}