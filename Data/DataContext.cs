using Microsoft.EntityFrameworkCore;
using VerifyEmailForgotPassword.Models;

namespace VerifyEmailForgotPassword.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
        }

        public DbSet<User> Users => Set<User>();
    }
}
