using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 用户等级状态。
    /// </summary>
    public enum UserLevelStatus
    {
        /// <summary>
        /// 已授权。
        /// </summary>
        Authorized = 0,
        /// <summary>
        /// 未授权。
        /// </summary>
        Unauthorized = 1,
        /// <summary>
        /// 未确认。
        /// </summary>
        Unconfirmed = 2
    }
}
