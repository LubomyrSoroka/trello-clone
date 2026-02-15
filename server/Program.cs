using Microsoft.EntityFrameworkCore;
using server.Data; // your DbContext namespace
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

// Read secrets from environment variables
builder.Configuration.AddEnvironmentVariables();
var jwtSecret = builder.Configuration["JWT_SECRET"];
var emailPassword= builder.Configuration["EMAIL_PASSWORD"];
var email = builder.Configuration["EMAIL"];
var clientUrl = builder.Configuration["CLIENT_URL"] ?? "http://localhost:5173";

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReact",
        policy =>
        {
            policy.WithOrigins(clientUrl) // frontend port
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
});

// Optionally register a service to provide them
builder.Services.AddSingleton(new SecretsService(jwtSecret, emailPassword, email, clientUrl));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var token = context.Request.Cookies["accessToken"];
            if (!string.IsNullOrEmpty(token))
                context.Token = token;
            return Task.CompletedTask;
        }
    };

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = "task-manager-app",
        ValidAudience = "task-manager-app",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
        //ClockSkew = TimeSpan.Zero // for testing puposes only
    };
});
var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");

// Add DbContext to DI container with connection string
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddScoped<IBoardService, BoardService>();




builder.Services.AddControllers();
var app = builder.Build();

app.UseRouting();

app.UseCors("AllowReact"); // 👈 Add this before app.UseAuthorization

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
