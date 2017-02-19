using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
{
    public class EnhancedAuthenticationClientHandler : IEnhancedAuthenticationClientHandler
    {
        public Task Authorize(EnhancedAuthenticationClientAuthorizeResult result)
        {
            //if (!result.IsSuccess)
            //{
            result.IsHandled = false;
            //}
            return Task.CompletedTask;
        }
    }
}
