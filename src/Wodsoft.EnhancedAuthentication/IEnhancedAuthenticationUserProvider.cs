using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证用户提供器。
    /// </summary>
    public interface IEnhancedAuthenticationUserProvider
    {
        /// <summary>
        /// 异步获取当前用户。
        /// </summary>
        /// <returns>返回增强认证用户。</returns>
        Task<IEnhancedAuthenticationUser> GetUserAsync();

        /// <summary>
        /// 获取登录地址。
        /// </summary>
        /// <param name="returnUrl">返回地址。</param>
        /// <returns>返回登录地址。</returns>
        string GetSignInUrl(string returnUrl);

        /// <summary>
        /// 获取确认地址。
        /// </summary>
        /// <param name="returnUrl">返回地址。</param>
        /// <returns>返回确认地址。</returns>
        string GetConfirmUrl(string returnUrl);
    }
}
