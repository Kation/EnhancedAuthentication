using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    public class EnhancedAuthenticationClientAuthorizeResult
    {
        public EnhancedAuthenticationClientAuthorizeResult(HttpContext context, UserToken token, string returnUrl)
        {
            HttpContext = context;
            IsSuccess = token != null;
            UserToken = token;
            IsHandled = false;
            Returnurl = returnUrl;
        }

        public HttpContext HttpContext { get; private set; }

        public bool IsSuccess { get; private set; }

        public UserToken UserToken { get; private set; }

        public bool IsHandled { get; set; }

        public string Returnurl { get; private set; }
    }
}
