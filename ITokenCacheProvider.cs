using System.Threading.Tasks;

namespace LightOAuth2
{
    public interface ITokenCacheProvider
    {
        Task SaveRefreshTokenAsync(string refreshToken);

        Task<string?> GetRefreshTokenAsync();

        Task DeleteRefreshTokenAsync();
    }
}