using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    public interface IEnhancedAuthenticationClientHandler
    {
        Task Authorize(EnhancedAuthenticationClientAuthorizeResult result);
    }
}
