﻿using System.ComponentModel.DataAnnotations;

namespace VerifyEmailForgotPassword.Models
{
    public class UserRegisterRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required , MinLength(6, ErrorMessage ="Please Enter at least 6 Cherecter")]
        public string Password { get; set; } = string.Empty;
        [Required, Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
