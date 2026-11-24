using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.EntityFramework.Extensions;
using ExternalIdp;
using ExternalIdp.Auth;
using ExternalIdp.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

// -------------------------------------------------------------------------
// External IDP deployment model
//
// An external IDP (simulated by MockIdpController) owns access token
// issuance. Bedrock manages credentials, MFA, passkeys, sessions, and
// audit — but defers JWT generation to MockTokenIssuer, which calls the
// external IDP's signing key.
//
// Key differences from the Embedded/Standalone samples:
//   - opts.Jwt.ExternalTokenIssuer = true  → Bedrock skips its own JWT Bearer
//   - JWT Bearer is configured manually to trust the external IDP's key
//   - IBedrockTokenIssuer is replaced with MockTokenIssuer
//   - opts.Jwt.SigningKey is still required for Bedrock's internal tokens
//     (MFA challenges, step-up tokens, enrollment tokens)
// -------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseSqlite(builder.Configuration.GetConnectionString("Default")));

// Configure JWT Bearer to trust the external IDP's signing key.
// In production this would point at the IDP's JWKS endpoint or authority.
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        var externalKey  = builder.Configuration["ExternalIdp:SigningKey"]!;
        var externalIss  = builder.Configuration["ExternalIdp:Issuer"]!;
        var externalAud  = builder.Configuration["ExternalIdp:Audience"]!;

        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer              = externalIss,
            ValidAudience            = externalAud,
            IssuerSigningKey         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(externalKey)),
            ValidateIssuerSigningKey = true,
            ClockSkew                = TimeSpan.Zero
        };
    });

builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.ExternalTokenIssuer = true;

        // Bedrock's internal signing key — used only for MFA challenge tokens,
        // step-up tokens, and enrollment tokens (never issued to end users).
        opts.Jwt.SigningKey = builder.Configuration["Jwt:InternalSigningKey"];

        opts.Email.FrontendBaseUrl = builder.Configuration["FrontendBaseUrl"]!;
        opts.Mfa.Issuer = "ExternalIdp Sample";

        opts.Password.CommonPasswordDenyListPath = "embedded";
    })
    .WithTokenIssuer<MockTokenIssuer>()
    .WithEmailSender<DevEmailSender>()
    .AddBedrockControllers();

builder.Services.AddControllers();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/error");

app.UseBedrock();
app.MapControllers();
app.Map("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));
app.Run();
