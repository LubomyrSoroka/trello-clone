using Microsoft.AspNetCore.Mvc;
using server.Data;
using server.Models;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.EntityFrameworkCore;

using System.Net.Mail;
using System.Net;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

using System.Security.Claims;
namespace TaskManagerAPI.Controllers;

using System.Security.Cryptography;
using BCrypt.Net;
using Microsoft.AspNetCore.Identity.Data;
using Npgsql.Replication;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly SecretsService _secrets;
    private readonly int _accessTokenExpirationMinutes = 15;
    private readonly int _refreshTokenExpirationDays = 7;

    private string websiteName => _secrets.ClientUrl;

    public AuthController(AppDbContext context, SecretsService secrets)
    {
        _secrets = secrets;
        _context = context;
    }
    [HttpGet("me")]
    public IActionResult Me()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken == null)
            return Unauthorized();
        string? email = ValidateRefreshToken(refreshToken);
        if (email == null)
            return Unauthorized();
        return Ok(new { Email = email });
    }

    [HttpGet("logout")]
    public IActionResult Logout()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken != null)
        {
            var tokenRecord = _context.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);
            if (tokenRecord != null)
            {
                // Revoke the token
                tokenRecord.Revoked = true;
                _context.SaveChanges();
            }
        }

        // Delete cookies
        Response.Cookies.Delete("refreshToken");
        Response.Cookies.Delete("accessToken");

        return Ok(new { message = "Logged out successfully" });
    }


    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
            return BadRequest(new { message = "No account with such an email exists." });
        if (user.Verified == false)
            return BadRequest(new { message = "Please verify your email." });
        if (BCrypt.Verify(request.Password, user.PasswordHash) == false)
            return BadRequest(new { message = "Incorrect password." });

        var accessToken = GenerateJwtToken(user.Email);

        var refreshToken = GenerateRefreshToken();
        var existingRefreshToken = _context.RefreshTokens.FirstOrDefault(rt => rt.Email == request.Email);
        if (existingRefreshToken != null)
        {
            existingRefreshToken.Token = refreshToken;
            existingRefreshToken.Expires = DateTime.UtcNow.AddDays(_refreshTokenExpirationDays);
            existingRefreshToken.Revoked = false;
        }
        else
        {
            _context.RefreshTokens.Add(new RefreshToken
            {
                Email = request.Email,
                Token = refreshToken,
                Expires = DateTime.UtcNow.AddDays(_refreshTokenExpirationDays),
                Revoked = false
            });
        }
        _context.SaveChanges();


        Response.Cookies.Append("accessToken", accessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // only over HTTPS
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddMinutes(_accessTokenExpirationMinutes),
        });

        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = false,
            Expires = DateTime.UtcNow.AddDays(_refreshTokenExpirationDays)
        });


        return Ok(new { });
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (_context.Users.FirstOrDefault(u => u.Email == request.Email) == null)
            return BadRequest(new { message = "User not found" });
        var Token = GenerateJwtToken(request.Email);
        return await sendEmail(request.Email, "Reset your password", $"Please click on this link to reset your password:\n{websiteName}/reset-password?token={Token}");
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var email = ValidateVerificationToken(request.Token);
        if (email == null)
            return BadRequest(new { message = "Invalid Token" });
        var user = _context.Users.FirstOrDefault(u => u.Email == email);
        if (user == null)
            return BadRequest(new { message = "User not found" });
        user.PasswordHash = BCrypt.HashPassword(request.NewPassword);
        _context.SaveChanges();
        return Ok(new { message = "Password reset successfully" });
    }

    public class TokenRequest
    {
        public string Token { get; set; }
    }

    [HttpPost("verify-token")]
    public async Task<IActionResult> VerifyToken([FromBody] TokenRequest request)
    {
        var email = ValidateVerificationToken(request.Token);
        if (email == null)
            return BadRequest(new { message = "Invalid Token" });

        var user = _context.Users.FirstOrDefault(u => u.Email == email);
        if (user == null)
            return BadRequest(new { message = "User not found" });

        return Ok(new { message = "Token is valid" });
    }


    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {

        Console.WriteLine($"Attempting to register {request.Email}");
        var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

        if (existingUser != null)
            return BadRequest(new { message = "EMAIL_EXISTS" });

        var Token = GenerateJwtToken(request.Email);

        var newUser = new User
        {
            Email = request.Email,
            PasswordHash = BCrypt.HashPassword(request.Password),
            Verified = false
        };

        _context.Users.Add(newUser);

        await _context.SaveChangesAsync();

        return await sendEmail(request.Email, "Register for The Task Manager App", $"Please click on this link to verify your email:\n{websiteName}/verify?token={Token}");


    }

    private async Task<IActionResult> sendEmail(string email, string subject, string body)
    {
        string myEmail = _secrets.PersonalEmail;
        string password = _secrets.EmailPassword;
        try
        {

            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential(myEmail, password),
                EnableSsl = true
            };
            var mailMessage = new MailMessage
            {
                From = new MailAddress(myEmail),
                Subject = subject,
                Body = body,
            };
            mailMessage.To.Add(email);

            await smtpClient.SendMailAsync(mailMessage);

            return Ok(new { message = "Email sent succesfully" });
        }
        catch (System.Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(500, new { message = "Failed to send email", error = ex.Message });
        }
    }
    [HttpPost("verify")]
    public IActionResult Verify([FromBody] VerifyRequest request)
    {
        Console.WriteLine("Verifying Token");
        var email = ValidateVerificationToken(request.Token);

        if (email == null)
            return BadRequest(new { message = "Invalid Token" });

        var existingUser = _context.Users.FirstOrDefault(u => u.Email == email);

        // could this error even happen?
        if (existingUser == null)
            return BadRequest(new { message = "User not found" });

        if (existingUser.Verified == true)
            return BadRequest(new { message = "Already verified" });

        existingUser.Verified = true;

        _context.SaveChanges();

        return Ok(new { message = "You have succesfully registered!" });
    }

    private string GenerateJwtToken(string email)
    {
        string myKey = _secrets.JwtSecret;
        // Your secret key — keep this in config or environment variables for real apps
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(myKey));


        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            // new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            // new Claim("id", user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, email)
            // Add more claims if needed, e.g. roles
        };

        var token = new JwtSecurityToken(
            issuer: "task-manager-app",
            audience: "task-manager-app",
            claims: claims,
            expires: DateTime.Now.AddMinutes(_accessTokenExpirationMinutes), // for testing puposes only
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string ValidateVerificationToken(string token)
    {
        string myKey = _secrets.JwtSecret;
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(myKey));

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "task-manager-app",
                ValidAudience = "task-manager-app",
                IssuerSigningKey = key
            }, out _);
            // Print all claims
            foreach (var claim in principal.Claims)
            {
                Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
            }
            return principal.FindFirst(ClaimTypes.Email)?.Value;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Token validation failed: {ex.Message}");
            return null;
        }
    }

    [HttpPost("refresh")]
    public IActionResult Refresh()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken == null)
            return Unauthorized();
        string? email = ValidateRefreshToken(refreshToken);
        if (email == null)
            return Unauthorized();

        var newJwt = GenerateJwtToken(email);
        Response.Cookies.Append("accessToken", newJwt, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // only over HTTPS
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddMinutes(_accessTokenExpirationMinutes),
        });

        return Ok();
    }

    private string? ValidateRefreshToken(string refreshToken)
    {
        var tokenRecord = _context.RefreshTokens
                .FirstOrDefault(rt => rt.Token == refreshToken);

        if (tokenRecord == null)
            return null; // not found

        if (tokenRecord.Expires < DateTime.UtcNow)
            return null; // expired

        if (tokenRecord.Revoked)
            return null; // explicitly revoked (e.g., logout)

        return tokenRecord.Email;
    }

    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
    public class RegisterRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class ForgotPasswordRequest
    {
        public string Email { get; set; }
    }

    public class ResetPasswordRequest
    {
        public string NewPassword { get; set; }
        public string Token { get; set; }
    }

    public class VerifyRequest
    {
        public string Token { get; set; }
    }
}
