using UserManagementApi.Models;

namespace UserManagementApi.Services.AuthService
{
    public interface IAuthService
    {
        Task<(int, string)> Registration(RegistrationModel model, string role);

        Task<TokenViewModel> Login(LoginModel model);

        Task<TokenViewModel> GetRefreshToken(GetRefreshTokenViewModel model);
    }
}
