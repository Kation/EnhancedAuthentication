using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    /// <summary>
    /// 增强认证客户端处理接口。
    /// </summary>
    public interface IEnhancedAuthenticationClientHandler
    {
        /// <summary>
        /// 授权处理。
        /// </summary>
        /// <param name="result">认证结果。</param>
        /// <returns></returns>
        Task Authorize(EnhancedAuthenticationClientAuthorizeResult result);
    }
}
