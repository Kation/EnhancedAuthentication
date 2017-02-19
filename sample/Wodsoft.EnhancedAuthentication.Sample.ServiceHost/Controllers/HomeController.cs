using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View();
        }

        public async Task<IActionResult> Init()
        {
            var databaseContext = HttpContext.RequestServices.GetRequiredService<IDatabaseContext>();
            var adminContext = databaseContext.GetContext<Admin>();
            if (await adminContext.CountAsync(adminContext.Query()) == 0)
            {
                var superAdmin = adminContext.Create();

                superAdmin.Username = "superAdmin";
                superAdmin.SetPassword("superAdmin");
                superAdmin.IsSystem = true;
                adminContext.Add(superAdmin);

                var admin = adminContext.Create();
                admin.Username = "admin";
                admin.SetPassword("admin");
                admin.IsSystem = false;
                adminContext.Add(admin);

                await databaseContext.SaveAsync();
            }
            return Content("Initialize Success.");
        }
    }
}
