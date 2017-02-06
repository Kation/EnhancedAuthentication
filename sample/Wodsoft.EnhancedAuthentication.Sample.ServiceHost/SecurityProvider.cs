using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Security;
using Microsoft.AspNetCore.Routing;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;
using Wodsoft.ComBoost.Data.Entity;
using System.Reflection;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class SecurityProvider : GeneralSecurityProvider
    {
        public SecurityProvider(IHttpContextAccessor httpContextAccessor, IDatabaseContext databaseContext)
        {
            if (httpContextAccessor == null)
                throw new ArgumentNullException(nameof(httpContextAccessor));
            if (httpContextAccessor.HttpContext == null)
                throw new ArgumentException(nameof(httpContextAccessor), "当前不存在Http上下文。");
            HttpContext = httpContextAccessor.HttpContext;
            RouteData = HttpContext.GetRouteData();
            PermissionTypeTokenName = "permissionType";
            DatabaseContext = databaseContext;
        }

        public IDatabaseContext DatabaseContext { get; private set; }

        public HttpContext HttpContext { get; private set; }

        public RouteData RouteData { get; private set; }

        public string PermissionTypeTokenName { get; private set; }

        protected virtual Type GetPermissionType()
        {
            return RouteData.DataTokens[PermissionTypeTokenName] as Type;
        }

        protected override async Task<IPermission> GetPermissionByIdentity(string identity)
        {
            var type = GetPermissionType();
            if (type == null)
                return null;
            if (type == typeof(Member))
            {
                var context = DatabaseContext.GetContext<Member>();
                var item = await context.GetAsync(identity);
                return item;
            }
            else if (type == typeof(Admin))
            {
                var context = DatabaseContext.GetContext<Admin>();
                var item = await context.GetAsync(identity);
                return item;
            }
            return null;
        }

        protected override async Task<IPermission> GetPermissionByUsername(string username)
        {
            var type = GetPermissionType();
            if (type == null)
                return null;
            if (type == typeof(Member))
            {
                var context = DatabaseContext.GetContext<Member>();
                var item = await context.SingleOrDefaultAsync(context.Query().Where(t => t.Username.ToLower() == username.ToLower()));
                return item;
            }
            else if (type == typeof(Admin))
            {
                var context = DatabaseContext.GetContext<Admin>();
                var item = await context.SingleOrDefaultAsync(context.Query().Where(t => t.Username.ToLower() == username.ToLower()));
                return item;
            }
            return null;
        }
    }
}
