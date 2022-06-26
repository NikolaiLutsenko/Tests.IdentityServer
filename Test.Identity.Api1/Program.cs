using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSingleton<RsaSecurityKey>(provider =>
{
    // It's required to register the RSA key with depedency injection.
    // If you don't do this, the RSA instance will be prematurely disposed.

    RSA rsa = RSA.Create();

    rsa.ImportRSAPublicKey(
        source: Convert.FromBase64String(builder.Configuration["Jwt:Asymmetric:PublicKey"]),
        bytesRead: out int _
    );

    return new RsaSecurityKey(rsa);
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        SecurityKey rsa = builder.Services.BuildServiceProvider().GetRequiredService<RsaSecurityKey>();

        options.IncludeErrorDetails = true; // <- great for debugging

        // Configure the actual Bearer validation
        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = rsa,
            ValidAudience = "jwt-test",
            ValidIssuer = "jwt-test",
            RequireSignedTokens = true,
            RequireExpirationTime = true, // <- JWTs are required to have "exp" property set
            ValidateLifetime = true, // <- the "exp" will be validated
            ValidateAudience = true,
            ValidateIssuer = true,
        };
    });
builder.Configuration.GetConnectionString("Identity");

builder.Services.AddSingleton<IAuthorizationHandler, AgeRequirementHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(name: "AgePolicy", policyBuilder =>
    {
        policyBuilder.Requirements.Add(new AgeRequirement(21));
    });
});

builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

internal class AgeRequirement : IAuthorizationRequirement
{
    public AgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }

    public int MinimumAge { get; }
}

internal class AgeRequirementHandler : AuthorizationHandler<AgeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AgeRequirement requirement)
    {
        var ageClaim = context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.DateOfBirth);
        if (ageClaim != null)
        {
            var age = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(ageClaim.Value));

            if (DateTimeOffset.UtcNow.AddYears(-age.Year).Year >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}
