using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证用户。
    /// </summary>
    public interface IEnhancedAuthenticationUser
    {
        /// <summary>
        /// 获取用户Id。
        /// </summary>
        string UserId { get; }

        /// <summary>
        /// 获取当前等级。
        /// </summary>
        byte CurrentLevel { get; }

        /// <summary>
        /// 获取最高等级。
        /// </summary>
        byte MaximumLevel { get; }
    }
}
