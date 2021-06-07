using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LightOAuth2
{
    public class Client
    {
        private readonly ClientOptions options;
        private TokenInfo? tokenInfo;

        private readonly JsonSerializerOptions jsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
        };

        public Client(ClientOptions options)
        {
            this.options = options;
        }

        public TokenInfo? CurrentTokenInfo
        {
            get => tokenInfo;
            set
            {
                tokenInfo = value;
                TokenInfoUpdated?.Invoke(this, new(tokenInfo));
            }
        }

        public event EventHandler<TokenInfoUpdatedEventArgs>? TokenInfoUpdated;

        private string RedirectUri => $"http://localhost:{options.RedirectPort}/";

        public async Task<bool> TryLoginAsync()
        {
            // Try to get token crom cache first
            if (options.TokenCache is not null)
            {
                var refreshToken = await options.TokenCache.GetRefreshTokenAsync().ConfigureAwait(false);
                if (refreshToken is not null)
                {
                    if (await TryRefreshTokenAsync(refreshToken).ConfigureAwait(false))
                        return true;
                }
            }
            // Start listener for redirect
            using var listener = StartCodeListener();

            // Make auth request
            OpenBrowserForAuth();

            // block on listener
            var (code, error) = await GetAccessCodeAsync(listener);
            if (code is null)
                return false;

            // use access code to get tokens
            var tokenResponse = await MakeTokenRequestAsync("authorization_code", code).ConfigureAwait(false);
            if (tokenResponse is not null)
            {
                if (options.TokenCache is not null)
                    await options.TokenCache.SaveRefreshTokenAsync(tokenResponse.RefreshToken).ConfigureAwait(false);
                CurrentTokenInfo = new(tokenResponse.AccessToken, tokenResponse.RefreshToken, TimeSpan.FromMinutes(tokenResponse.ExpiresIn));
                return true;
            }

            return false;
        }

        private HttpListener StartCodeListener()
        {
            var listener = new HttpListener();
            listener.Prefixes.Add(RedirectUri);
            listener.Start();
            return listener;
        }

        public async Task<bool> TryRefreshTokenAsync(string refreshToken, bool tryReauth = false)
        {
            var tokenInfo = await MakeTokenRequestAsync("refresh_token", refreshToken);
            if (tokenInfo is not null)
            {
                CurrentTokenInfo = new TokenInfo(tokenInfo.AccessToken, tokenInfo.RefreshToken, TimeSpan.FromMinutes(tokenInfo.ExpiresIn));
                if (options.TokenCache is not null)
                {
                    await options.TokenCache.SaveRefreshTokenAsync(tokenInfo.RefreshToken).ConfigureAwait(false);
                }
                return true;
            }
            else if (options.TokenCache is not null)
                await options.TokenCache.DeleteRefreshTokenAsync().ConfigureAwait(false);

            return tryReauth && await TryLoginAsync().ConfigureAwait(false); // if told to try reauth, try it,  otherwise this returns false
        }

        private async Task<TokenResponse?> MakeTokenRequestAsync(string grantType, string code)
        {
            using var httpClient = new HttpClient();
            using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, options.TokenUrl);
            tokenRequest.Content = new FormUrlEncodedContent(GetFormContent(grantType, code));
            var response = await httpClient.SendAsync(tokenRequest);
            var responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
                return null;

            var responseStream = await response.Content.ReadAsStreamAsync();
            var tokenResponse = await JsonSerializer.DeserializeAsync<TokenResponse>(responseStream, jsonOpts);
            return tokenResponse;
        }

        private IEnumerable<KeyValuePair<string?, string?>> GetFormContent(string grantType, string code, byte[]? code_verifier = null)
            => grantType switch
            {
                "authorization_code" => options.AuthorizationProvider.GetAccessTokenParams(code),
                "refresh_token" => new Dictionary<string, string?>
                {
                    { "client_id", options.ClientId },
                    { "grant_type", grantType },
                    { "refresh_token", code }
                },
                _ => throw new InvalidOperationException($"Unexpected grant_type {grantType}")
            } as IEnumerable<KeyValuePair<string?, string?>>;

        private static async Task<(string? Code, string? Error)> GetAccessCodeAsync(HttpListener listener)
        {
            var context = await listener.GetContextAsync();
            var request = context.Request;
            var redirectParams = request.QueryString;
            var code = GetAccessCodeFromParams(redirectParams, out string? error);
            var response = context.Response;
            var buffer = Encoding.UTF8.GetBytes("<html><body>Application has been authorized. Please close this window and return to the app.</body></html>");
            response.ContentLength64 = buffer.Length;
            var output = response.OutputStream;
            output.Write(buffer, 0, buffer.Length);
            output.Close();
            listener.Stop();

            return (code, error);
        }

        private void OpenBrowserForAuth()
        {
            var queryParams = options.AuthorizationProvider.GetAuthorizationParams(options.Scope);
            var authUrl = QueryHelpers.AddQueryString(options.AuthUrl, queryParams);
            var processInfo = new ProcessStartInfo()
            {
                FileName = authUrl,
                UseShellExecute = true
            };
            Process.Start(processInfo);
        }

        private static string? GetAccessCodeFromParams(NameValueCollection queryParams, out string? error)
        {
            error = queryParams.Get("error");
            if (error is not null)
                return null;

            if (queryParams.Get("code") is string code)
                return code;

            return null;
        }
    }
}