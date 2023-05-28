using Microsoft.AspNetCore.Mvc;

namespace Authentication_Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        [HttpPost("authenticate")]
        public ActionResult<String> Index(AuthenticationRequestBody authenticationRequestBody)
        {
            return View();
        }
    }

    public class AuthenticationRequestBody
    {
        public string? UserName { get; set; }
        public string? Password { get; set; }
    }
}
