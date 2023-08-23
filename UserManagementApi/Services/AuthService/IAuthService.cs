using UserManagementApi.Models;

namespace UserManagementApi.Services.AuthService
{
    public interface IAuthService
    {
        Task<(int, string)> Registration(RegistrationModel model, string role);

        Task<(int, string)> Login(LoginModel model);
    }
}
