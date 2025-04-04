using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace phantom.MVC.MuOnline
{
    public class ConfigJwtBearerService
    {
        public static IServiceCollection ConfigServiceJwtBearer(IServiceCollection services, byte[] jwtSecretKey)
        {
            // Configure jwt authentication
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(jwtSecretKey),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    LifetimeValidator = (before, expires, token, param) =>
                    {
                        return expires > DateTime.UtcNow;
                    }
                };
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("Read", policy => policy.RequireClaim("scope", "read:users"));
                options.AddPolicy("Write", policy => policy.RequireClaim("scope", "write:users"));
                options.AddPolicy("User", policy => policy.RequireAssertion(context =>
                {
                    var scopeClaim = context.User.FindFirst("scope")?.Value;
                    if (string.IsNullOrEmpty(scopeClaim))
                    {
                        return false;
                    }
                    var scopes = scopeClaim.Split(' ');
                    return scopes.Contains("read:users") || scopes.Contains("write:users");
                }));
                options.AddPolicy("Refresh", policy => policy.RequireClaim("scope", "read:refresh"));
                options.AddPolicy("Admin", policy => policy.RequireClaim("scope", "admin:users"));
            });

            return services;
        }
    }
}
