using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Wodsoft.ComBoost.Mvc;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class MemberController : EntityController<Member>
    {

    }
}
