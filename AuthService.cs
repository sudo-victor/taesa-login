using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Taesa.Auth
{
    public class AuthService
    {
        public readonly string ApplicationUser;
        public readonly string ApplicationPassword;
        public readonly string ApplicationUrl;

        public AuthService(string url, string applicationUser, string applicationPassword)
        {
            ApplicationPassword = applicationPassword;
            ApplicationUser = applicationUser;
            ApplicationUrl = url;
        }

        private HttpClient GetClient()
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "application/json");

            return client;
        }

        private MultipartFormDataContent FormDataContent(string key)
        {
            return new()
            {
                {new StringContent(ApplicationUser), "login"},
                {new StringContent(ApplicationPassword), "senha"},
                {new StringContent(key), "chave_acesso"}
            };
        }

        public async Task<User> Authenticate(string key)
        {
            using var client = GetClient();
            var body = FormDataContent(key);
            var response = await client.PostAsync(ApplicationUrl, body);
            if (!response.IsSuccessStatusCode)
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        throw new AuthException("Não autorizado");
                    default:
                        throw new AuthException("Erro no servidor");
                }
            }

            var tokenHeader = response.Headers.GetValues("Token").FirstOrDefault() ??
                              throw new AuthException("Token não fornecido");

            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(tokenHeader))
            {
                throw new AuthException("O token não pode ser lido!");
            }

            var jwtToken = handler.ReadJwtToken(tokenHeader);
            return JsonConvert.DeserializeObject<User>(jwtToken.Payload.SerializeToJson());
        }
    }
}