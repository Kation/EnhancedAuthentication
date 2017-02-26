using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost.Security;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
{
    public class EnhancedAuthenticationClientHandler : IEnhancedAuthenticationClientHandler
    {
        public Task Authorize(EnhancedAuthenticationClientAuthorizeResult result)
        {
            if (result.IsSuccess)
            {
                var authenticationProvider = result.HttpContext.RequestServices.GetRequiredService<IAuthenticationProvider>();
                if (result.UserToken)                
                //authenticationProvider.SignInAsync()
                result.IsHandled = false;
            }
            return Task.CompletedTask;
        }
    }
}
