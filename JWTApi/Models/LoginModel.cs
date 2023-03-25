using System.ComponentModel.DataAnnotations;

namespace JWTApi.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "UserName Is Required")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Password Is Required")]
        public string? Password { get; set; }
    }
}
