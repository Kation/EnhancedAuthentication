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
        private IDatabaseContext _DatabaseContext;
        public ThirdPartSecurityProvider(IDatabaseContext databaseContext)
        {
            _DatabaseContext = databaseContext;
        }

        public string ConvertRoleToString(object role)
        {
            return role.ToString();
        }

        public async Task<IPermission> GetPermissionAsync(string identity)
        {
            var memberContext = _DatabaseContext.GetContext<Member>();
            var member = await memberContext.GetAsync(identity);
            return member;
        }

        public Task<IPermission> GetPermissionAsync(IDictionary<string, string> properties)
        {
            throw new NotSupportedException();
        }
    }
}
