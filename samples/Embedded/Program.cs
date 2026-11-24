using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Embedded;
using Embedded.Infrastructure;
using Microsoft.EntityFrameworkCore;

// -------------------------------------------------------------------------
// Embedded deployment model
//
// Auth and business data share one database. AppDbContext inherits from
// BedrockContext (auth tables in the "auth" schema) and adds application
// tables alongside them.
// -------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.Issuer    = builder.Configuration["Jwt:Issuer"]!;
        opts.Jwt.Audience  = builder.Configuration["Jwt:Audience"]!;
        opts.Jwt.SigningKey = builder.Configuration["Jwt:SigningKey"];

        opts.Email.FrontendBaseUrl = builder.Configuration["FrontendBaseUrl"]!;
        opts.Mfa.Issuer = "Embedded Sample";

        opts.Password.CommonPasswordDenyListPath = "embedded";
    })
    .WithEmailSender<DevEmailSender>()
    .AddBedrockControllers();

builder.Services.AddControllers();

var app = builder.Build();

// Create tables on first run (use migrations in production)
using (var scope = app.Services.CreateScope())
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/error");

app.UseBedrock();
app.MapControllers();
app.Map("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));
app.Run();
