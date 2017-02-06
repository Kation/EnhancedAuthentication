using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Mvc;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Domains;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Controllers
{
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


        public IActionResult Confirm()
        {
            if (!User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(string password)
        {
            if (!User.Identity.IsAuthenticated)
                return StatusCode(200);
            var memberDomain = DomainProvider.GetService<AccountDomainService>();
            var context = CreateDomainContext();
            try
            {
                await memberDomain.ExecuteAsync(context, "Confirm");
            }
            catch (UnauthorizedAccessException ex)
            {
                return StatusCode(401, ex.Message);
            }
            return StatusCode(200);
        }

        public IActionResult SignUp()
        {
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(string username)
        {
            if (User.Identity.IsAuthenticated)
                return StatusCode(200);
            var memberDomain = DomainProvider.GetService<AccountDomainService>();
            var context = CreateDomainContext();
            try
            {
                await memberDomain.ExecuteAsync(context, "SignUp");
            }
            catch (ArgumentException ex)
            {
                return StatusCode(400, ex.Message);
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
