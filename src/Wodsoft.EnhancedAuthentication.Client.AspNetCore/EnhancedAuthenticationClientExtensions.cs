using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// 增强认证客户端扩展方法。
    /// </summary>
    public static class EnhancedAuthenticationClientExtensions
    {
        /// <summary>
        /// 使用增强认证客户端。
        /// </summary>
        /// <param name="app">应用构造器。</param>
        /// <param name="options">配置选项。</param>
        public static void UseEnhancedAuthenticationClient(this IApplicationBuilder app, EnhancedAuthenticationClientMiddlewareOptions options)
        {
            //var client = app.ApplicationServices.GetRequiredService<EnhancedAuthenticationClient>();
            app.UseMiddleware<EnhancedAuthenticationClientMiddleware>(options);
        }
    }
}