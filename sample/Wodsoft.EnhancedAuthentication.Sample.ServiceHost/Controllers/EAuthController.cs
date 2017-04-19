using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Wodsoft.EnhancedAuthentication.MvcCore;
using Wodsoft.ComBoost.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Controllers
{
    public class EAuthController : EnhancedAuthenticationController
    {
        protected override Task ApplyCertificateCore(AppInformation appInfo, string callbakUrl)
        {
            return Task.CompletedTask;
        }

        protected override async Task<bool> CheckIsAdmin(string username, string password)
        {
            if (username == null || password == null)
                return false;
            var databaseContext = HttpContext.RequestServices.GetRequiredService<IDatabaseContext>();
            var adminContext = databaseContext.GetContext<Admin>();
            var admin = await adminContext.SingleOrDefaultAsync(adminContext.Query().Where(t => t.Username.ToLower() == username.ToLower()));
            if (admin == null)
                return false;
            return admin.VerifyPassword(password);
        }

        public async Task<IActionResult> GetUserInfo(Guid id)
        {
            try
            {
                VerifyServiceRequest();
            }
            catch (ArgumentNullException ex)
            {
                return BadRequest();
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized();
            }
            var databaseContext = HttpContext.RequestServices.GetRequiredService<IDatabaseContext>();
            var memberContext = databaseContext.GetContext<Member>();
            var member = await memberContext.GetAsync(id);
            if (member == null)
                return NotFound();
            return Content(Newtonsoft.Json.JsonConvert.SerializeObject(new
            {
                Username = member.Username
            }));
        }
    }
}
