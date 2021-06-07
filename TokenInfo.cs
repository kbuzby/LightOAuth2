using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LightOAuth2
{
    public record TokenInfo(string AccessToken, string RefreshToken, TimeSpan ExpiresIn)
    {
    }
}
