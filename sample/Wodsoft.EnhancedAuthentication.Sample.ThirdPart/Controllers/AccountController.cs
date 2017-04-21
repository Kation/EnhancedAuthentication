using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Wodsoft.ComBoost.Security;
using Microsoft.Extensions.DependencyInjection;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Authorize()
        {
            return View();
        }

        public async Task<IActionResult> SignOut(string returnUrl = "/")
        {
            if (User.Identity.IsAuthenticated)
            {
                await HttpContext.RequestServices.GetRequiredService<IAuthenticationProvider>().SignOutAsync();
            }
            return Redirect(returnUrl);
        }
    }
}
