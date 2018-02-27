using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    /// <summary>
    /// 增强认证客户端授权结果。
    /// </summary>
    public class EnhancedAuthenticationClientAuthorizeResult
    {
        /// <summary>
        /// 实例化授权结果。
        /// </summary>
        /// <param name="context">Http上下文。</param>
        /// <param name="token">用户令牌。</param>
        /// <param name="returnUrl">返回地址。</param>
        public EnhancedAuthenticationClientAuthorizeResult(HttpContext context, UserToken token, string returnUrl)
        {
            HttpContext = context;
            IsSuccess = token != null;
            UserToken = token;
            IsHandled = false;
            Returnurl = returnUrl;
        }

        /// <summary>
        /// 获取Http上下文。
        /// </summary>
        public HttpContext HttpContext { get; private set; }

        /// <summary>
        /// 获取是否授权成功。
        /// </summary>
        public bool IsSuccess { get; private set; }

        /// <summary>
        /// 获取用户令牌。
        /// </summary>
        public UserToken UserToken { get; private set; }

        /// <summary>
        /// 获取或设置是否已处理。
        /// </summary>
        public bool IsHandled { get; set; }

        /// <summary>
        /// 获取返回地址。
        /// </summary>
        public string Returnurl { get; private set; }
    }
}
