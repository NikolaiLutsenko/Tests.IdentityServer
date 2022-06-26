using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Test.IdentityServer.Services;

public interface IJwtGenerator
{
    Task<JwtSecurityToken> Generate(IdentityUser identityUser);
}

class JwtGenerator : IJwtGenerator
{
    private readonly IConfiguration configuration;
    private readonly UserManager<IdentityUser> userManager;

    public JwtGenerator(IConfiguration configuration, UserManager<IdentityUser> userManager)
    {
        this.configuration = configuration;
        this.userManager = userManager;
    }

    public async Task<JwtSecurityToken> Generate(IdentityUser identityUser)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey( // Convert the loaded key from base64 to bytes.
            source: Convert.FromBase64String(configuration["Jwt:Asymmetric:PrivateKey"]), // Use the private key to sign tokens
            bytesRead: out int _); // Discard the out variable 

        var signingCredentials = new SigningCredentials(
            key: new RsaSecurityKey(rsa),
            algorithm: SecurityAlgorithms.RsaSha256 // Important to use RSA version of the SHA algo 
        )
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var claims = new List<Claim>();
        foreach (var claim in await userManager.GetClaimsAsync(identityUser))
        {
            claims.Add(claim);
        }
        foreach (var role in await userManager.GetRolesAsync(identityUser))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        claims.Add(new Claim(ClaimTypes.Name, identityUser.UserName));
        claims.Add(new Claim(ClaimTypes.Email, identityUser.Email));
        claims.Add(new Claim(ClaimTypes.DateOfBirth, new DateTimeOffset(new DateTime(1993, 01, 5)).ToUnixTimeSeconds().ToString()));


        DateTime jwtDate = DateTime.Now;
        return new JwtSecurityToken(
            audience: "jwt-test",
            issuer: "jwt-test",
            claims: claims,
            notBefore: jwtDate,
            expires: jwtDate.AddMinutes(60),
            signingCredentials: signingCredentials
        );
    }
}