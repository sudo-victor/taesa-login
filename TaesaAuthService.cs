using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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


            var identity = new ClaimsIdentity(token.Claims.Concat(new[]
                {
                    new Claim("header", token.RawHeader),
                    new Claim("signature", token.RawSignature)
                })
            );
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

        public async Task<string> LoginAsync(string chaveAcesso)
        {
            var token = await Authenticate(chaveAcesso);
            return GenerateToken(token);
        }

        public User GetUser(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                throw new AuthException("O token não pode ser lido!");
            }

            var jwtToken = handler.ReadJwtToken(token);
            var json = jwtToken.Payload.SerializeToJson();


            var jUser = JObject.Parse(json);

            var response = JsonConvert.DeserializeObject<UserResponse>(json);
            if (response is null)
                throw new AuthException("Não foi possível extrair as informações do usuário");

            var user = new User()
            {
                Email = response.Email,
                Nome = response.Nome,
                Id_Usuario = response.Id_Usuario,
                Grupos = new List<Grupo>()
            };


            if (jUser.ContainsKey("grupos"))
            {
                if (jUser["grupos"].Type == JTokenType.Array)
                {
                    user.Grupos = jUser["grupos"].ToObject<List<Grupo>>();
                }
                else
                {
                    var grupo = jUser["grupos"].ToObject<Grupo>();
                    user.Grupos = new List<Grupo>() {grupo};
                }
            }
            else
            {
                throw new AuthException("Grupos não encontrato");
            }

            return user;
        }
    }
}