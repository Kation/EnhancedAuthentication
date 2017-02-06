using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.ComBoost.Security;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Areas.Admin.Domains
{
    public class AccountDomainService : DomainService
    {
        public async Task SignIn([FromService] IAuthenticationProvider authenticationProvider, [FromValue] string username, [FromValue] string password)
        {
            if (authenticationProvider.GetAuthentication().Identity.IsAuthenticated)
                return;
            bool result = await authenticationProvider.SignInAsync(new Dictionary<string, string>
            {
                { "username", username },
                { "password", password }
            });
            if (!result)
                throw new UnauthorizedAccessException("用户名或密码不正确");
        }

        public async Task SignOut([FromService] IAuthenticationProvider authenticationProvider)
        {
            if (!authenticationProvider.GetAuthentication().Identity.IsAuthenticated)
                return;
            await authenticationProvider.SignOutAsync();
        }
    }
}
