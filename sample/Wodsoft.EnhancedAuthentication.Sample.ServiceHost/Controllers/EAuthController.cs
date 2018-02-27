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
    public class EAuthController : EnhancedAuthenticationCertificateController
    {
        protected override Task ApplyCertificateCore(AppInformation appInfo, string callbakUrl)
        {
            return Task.CompletedTask;
        }

        protected override Task<bool> CheckIsAdminAsync()
        {
            return Task.FromResult(true);
        }

        public async Task<IActionResult> GetUserInfo(Guid id)
        {
            try
            {
                HttpContext.VerifyServiceRequest("root.userinfo");
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
