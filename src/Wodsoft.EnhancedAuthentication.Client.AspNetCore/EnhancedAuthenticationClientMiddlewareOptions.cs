using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    /// <summary>
    /// 增强认证客户端中间件选项。
    /// </summary>
    public class EnhancedAuthenticationClientMiddlewareOptions
    {
        /// <summary>
        /// 获取或设置基础路径。
        /// </summary>
        public PathString BasePath { get; set; }

        /// <summary>
        /// 获取或设置授权地址。
        /// </summary>
        public string AuthorizeUrl { get; set; }
    }
}
