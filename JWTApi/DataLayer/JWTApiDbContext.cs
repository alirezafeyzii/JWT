using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTApi.DataLayer
{
    public class JWTApiDbContext : IdentityDbContext<IdentityUser>
    {
        public JWTApiDbContext(DbContextOptions<JWTApiDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);  
        }
    }
}
