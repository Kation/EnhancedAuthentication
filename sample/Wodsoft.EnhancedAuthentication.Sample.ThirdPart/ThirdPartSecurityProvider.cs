using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.ComBoost.Security;
using Wodsoft.EnhancedAuthentication.Sample.ThirdPart.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
{
    public class ThirdPartSecurityProvider : ISecurityProvider
    {
        private HttpContext _HttpContext;
        public ThirdPartSecurityProvider(IHttpContextAccessor httpContextAccessor)
        {
            _HttpContext = httpContextAccessor.HttpContext;
        }

        public string ConvertRoleToString(object role)
        {
            return role.ToString();
        }

        public async Task<IPermission> GetPermissionAsync(string identity)
        {
            var databaseContext = _HttpContext.RequestServices.GetRequiredService<IDatabaseContext>();
            var memberContext = databaseContext.GetContext<Member>();
            var member = await memberContext.GetAsync(identity);
            return member;
        }

        public Task<IPermission> GetPermissionAsync(IDictionary<string, string> properties)
        {
            throw new NotSupportedException();
        }
    }
}
