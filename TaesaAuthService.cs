using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Taesa.Auth
{
    public class TaesaAuthService
    {
        public readonly string ApplicationUser;
        public readonly string ApplicationPassword;
        public readonly string ApplicationUrl;
        public SecurityKey Key { get; }

        public TaesaAuthService(SecurityKey applicationScretKey, string url, string applicationUser,
            string applicationPassword)
        {
            ApplicationPassword = applicationPassword;
            ApplicationUser = applicationUser;
            ApplicationUrl = url;
            Key = applicationScretKey; 
        }

        public TaesaAuthService(SecurityKey key, TaesaAuthSettings settings) : this(key,
            settings.Url, settings.User,
            settings.Password)
        {
        }

        private HttpClient GetClient()
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "application/json");

            return client;
        }

        private MultipartFormDataContent FormDataContent(string key)
        {
            return new MultipartFormDataContent()
            {
                {new StringContent(ApplicationUser), "login"},
                {new StringContent(ApplicationPassword), "senha"},
                {new StringContent(key), "chave_acesso"}
            };
        }

        public string GenerateToken(JwtSecurityToken token)
        {
            var handler = new JwtSecurityTokenHandler();
            var identity = new ClaimsIdentity(new[]
            {
                new Claim("TaesaToken", token.RawData)
            });
            var tokenDescriptior = new SecurityTokenDescriptor()
            {
                Subject = identity,
                Audience = "TaesaAudience",
                Issuer = "TaesaIssuer",
                Expires = token.ValidTo,
                NotBefore = token.ValidFrom,
                SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256Signature)
            };
            var wrapped = handler.CreateJwtSecurityToken(tokenDescriptior);
            return handler.WriteToken(wrapped);
        }

        public async Task<JwtSecurityToken> Authenticate(string key)
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

            if (jwtToken.ValidTo < DateTime.Now)
                throw new SecurityTokenExpiredException();
            return jwtToken;
        }

        public async Task<string> Login(string chaveAcesso)
        {
            var token = await Authenticate(chaveAcesso);
            return GenerateToken(token);
        }
    }
}