﻿using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Wodsoft.ComBoost.Security;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class EnhancedAuthenticationUserProvider : IEnhancedAuthenticationUserProvider
    {
        private IAuthentication _Authentication;
        private HttpContext _HttpContext;

        public EnhancedAuthenticationUserProvider(IHttpContextAccessor httpContextAccessor, IAuthenticationProvider authenticationProvider)
        {
            _Authentication = authenticationProvider.GetAuthentication();
            _HttpContext = httpContextAccessor.HttpContext;
        }

        public UserLevelStatus CheckLevel(IEnhancedAuthenticationUser user, string level)
        {
            AccessLevel accessLevel, current, max;
            if (!Enum.TryParse<AccessLevel>(level, out accessLevel))
                return UserLevelStatus.Unauthorized;
            if (!Enum.TryParse<AccessLevel>(user.CurrentLevel, out current))
                return UserLevelStatus.Unauthorized;
            if (!Enum.TryParse<AccessLevel>(user.MaximumLevel, out max))
                return UserLevelStatus.Unauthorized;
            if ((int)accessLevel >= (int)current)
                return UserLevelStatus.Authorized;
            if ((int)accessLevel >= (int)max)
                return UserLevelStatus.Unconfirmed;
            return UserLevelStatus.Unauthorized;
        }

        public string GetConfirmUrl(string returnUrl)
        {
            returnUrl = Convert.ToBase64String(Encoding.ASCII.GetBytes(returnUrl));
            string url = _HttpContext.Request.PathBase.Add("/Account/Confirm") + "?returnUrl=" + Uri.EscapeDataString(returnUrl);
            return url;
        }

        public string GetSignInUrl(string returnUrl)
        {
            returnUrl = Convert.ToBase64String(Encoding.ASCII.GetBytes(returnUrl));
            string url = _HttpContext.Request.PathBase.Add("/Account/SignIn") + "?returnUrl=" + Uri.EscapeDataString(returnUrl);
            return url;
        }

        public async Task<IEnhancedAuthenticationUser> GetUserAsync()
        {
            if (!_Authentication.Identity.IsAuthenticated)
                return null;
            var member = await _Authentication.GetPermission<Member>();
            var user = new EAuthUser()
            {
                UserId = member.Index.ToString(),
                CurrentLevel = "LevelE",
                MaximumLevel = member.Level.ToString()
            };
            return user;
        }
    }
}
