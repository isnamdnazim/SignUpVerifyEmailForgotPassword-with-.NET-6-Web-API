using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using VerifyEmailForgotPassword.Data;
using VerifyEmailForgotPassword.Models;

namespace VerifyEmailForgotPassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        public readonly DataContext _dataContext;
        public UserController(DataContext dataContext)
        {
            _dataContext = dataContext;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegisterRequest request)
        {
            if(_dataContext.Users.Any(u => u.Email == request.Email))
            {
                return BadRequest("User Already Exists");
            }

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };

            _dataContext.Users.Add(user);
            await _dataContext.SaveChangesAsync();

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<IActionResult> login(UserLoginRequest request)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if(user == null)
            {
                return BadRequest("User Not Found");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password is Incorrect");
            }

            if (user.VerifiedAt == null)
            {
                return BadRequest("User Not Verified");
            }
            

            return Ok($"Welcome Back, {user.Email} !");
        }

        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.VerificationToken == token);
            if (user == null)
            {
                return BadRequest("Invalid Token");
            }

            user.VerifiedAt = DateTime.Now;
            await _dataContext.SaveChangesAsync();


            return Ok("User Verified! ");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                return BadRequest("User not Found");
            }

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            await _dataContext.SaveChangesAsync();


            return Ok("You can reset your password");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token);
            if (user == null || user.ResetTokenExpires < DateTime.Now)
            {
                return BadRequest("Invalid Token.");
            }

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;

            await _dataContext.SaveChangesAsync();


            return Ok("Password Successfully Reset");
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedPasswordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedPasswordHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
    }
}
