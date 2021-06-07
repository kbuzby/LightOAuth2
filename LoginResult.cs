using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LightOAuth2
{
    public class LoginResult
    {
        public TokenInfo? TokenInfo { get; init; }
        public string? Error { get; init; }
    }
}
