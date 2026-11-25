using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Microsoft.EntityFrameworkCore;
using Standalone;
using Standalone.Infrastructure;

// -------------------------------------------------------------------------
// Standalone deployment model
//
// This service is a dedicated auth microservice. It exposes all Bedrock
// endpoints and publishes its public signing key at /.well-known/jwks.json.
// Other services in your system validate incoming JWTs against that endpoint
// without calling back to this service on every request.
//
// Other services configure JWT Bearer like this:
//
//   builder.Services
//       .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//       .AddJwtBearer(opts =>
//       {
//           opts.Authority        = "https://auth.yourapp.com";
//           opts.Audience         = "yourapp";
//           opts.MetadataAddress  = "https://auth.yourapp.com/.well-known/jwks.json";
//       });
// -------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AuthDbContext>(opts =>
    opts.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddBedrockEntityFramework<AuthDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.Issuer    = builder.Configuration["Jwt:Issuer"]!;
        opts.Jwt.Audience  = builder.Configuration["Jwt:Audience"]!;
        opts.Jwt.SigningKey = builder.Configuration["Jwt:SigningKey"];

        opts.Email.FrontendBaseUrl = builder.Configuration["FrontendBaseUrl"]!;
        opts.Mfa.Issuer = "Standalone Sample";

        opts.Password.CommonPasswordDenyListPath = "embedded";
    })
    .WithEmailSender<DevEmailSender>()
    .AddBedrockControllers();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureCreatedAsync();

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/error");

app.UseBedrock();
app.MapControllers();
app.Map("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));
app.Run();
