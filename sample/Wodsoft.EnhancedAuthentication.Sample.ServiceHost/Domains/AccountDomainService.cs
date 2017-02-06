using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.ComBoost.Security;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Domains
{
    public class AccountDomainService : DomainService
    {
        public async Task Confirm([FromService] IAuthenticationProvider authenticationProvider, [FromValue] string password)
        {
            var authentication = authenticationProvider.GetAuthentication();
            if (!authentication.Identity.IsAuthenticated)
                throw new UnauthorizedAccessException("当前没有用户登录。");
            var member = await authentication.GetPermission<Member>();
            if (!member.VerifyPassword(password))
                throw new UnauthorizedAccessException("用户名或密码不正确");
        }


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

        public async Task SignUp([FromService] IAuthenticationProvider authenticationProvider,
            [FromService] IDatabaseContext databaseContext, [FromValue] string username, [FromValue] string password)
        {
            if (authenticationProvider.GetAuthentication().Identity.IsAuthenticated)
                return;
            if (username.Length < 3)
                throw new ArgumentException("用户名不能小于3位。");
            if (password.Length < 3)
                throw new ArgumentException("密码不能小于3位。");
            username = username.Trim();
            var memberContext = databaseContext.GetContext<Member>();
            var count = await memberContext.CountAsync(memberContext.Query().Where(t => t.Username.ToLower() == username.ToLower()));
            if (count != 0)
                throw new ArgumentException("用户名已存在。");
            var member = memberContext.Create();
            member.Username = username;
            member.SetPassword(password);
            member.Level = AccessLevel.LevelE;
            memberContext.Add(member);
            await databaseContext.SaveAsync();
            await authenticationProvider.SignInAsync(member);
        }
    }
}
