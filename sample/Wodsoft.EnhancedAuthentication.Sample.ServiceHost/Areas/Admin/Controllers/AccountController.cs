using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Mvc;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Areas.Admin.Domains;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class AccountController : DomainController
    {
        public IActionResult SignIn()
        {
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(string username)
        {
            if (User.Identity.IsAuthenticated)
                return StatusCode(200);
            var memberDomain = DomainProvider.GetService<AccountDomainService>();
            var context = CreateDomainContext();
            try
            {
                await memberDomain.ExecuteAsync(context, "SignIn");
            }
            catch (UnauthorizedAccessException ex)
            {
                return StatusCode(401, ex.Message);
            }
            return StatusCode(200);
        }

        public async Task<IActionResult> SignOut(string returnUrl)
        {
            if (!User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            var memberDomain = DomainProvider.GetService<AccountDomainService>();
            var context = CreateDomainContext();
            await memberDomain.ExecuteAsync(context, "SignOut");
            if (returnUrl != null)
                return Redirect(returnUrl);
            else
                return RedirectToAction("Index", "Home");
        }
    }
}
