using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Taesa.Auth
{
    public static class AuthExtension
    {
        public static IServiceCollection AddAuthorizationTaesa(this IServiceCollection services, SecurityKey key,
            TaesaAuthSettings settings)
        {
            var authService = new TaesaAuthService(key, settings);
            services.AddSingleton(authService);
            return services;
        }

        public static IServiceCollection AddAuthorizationTaesa(this IServiceCollection services, SecurityKey key,
            string url,
            string applicationUser, string applicationPassword)
        {
            var authService = new TaesaAuthService(key, url, applicationUser, applicationPassword);
            services.AddSingleton(authService);
            return services;
        }

        public static AuthenticationBuilder AddAuthenticationTaesa(this IServiceCollection services, SecurityKey key,
            Action<JwtBearerOptions> configureOptions = null)
        {
            return services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;

                x.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = "TaesaIssuer",
                    ValidAudience = "TaesaAudience",
                    IssuerSigningKey = key,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                };
                if (configureOptions != null)
                {
                    configureOptions(x);
                }
            });
        }

        public static void AddAuthTaesa(this IServiceCollection services, TaesaAuthSettings settings,
            Action<JwtBearerOptions> configureOptions = null)
        {
            var key = new SymmetricSecurityKey(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(settings.Key)));
            services.AddAuthorizationTaesa(key, settings);
            services.AddAuthenticationTaesa(key, configureOptions);
        }
    }
}