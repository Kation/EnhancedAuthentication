using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 用户令牌。
    /// </summary>
    public class UserToken
    {
        /// <summary>
        /// 获取或设置用户Id。
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// 获取或设置当前等级。
        /// </summary>
        public byte CurrentLevel { get; set; }

        /// <summary>
        /// 获取或设置最大等级。
        /// </summary>
        public byte MaximumLevel { get; set; }
    }
}
