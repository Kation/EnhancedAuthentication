using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证安全票据。
    /// </summary>
    public class EnhancedAuthenticationSecurityTicket
    {
        /// <summary>
        /// 获取或设置过期时间毫秒数。
        /// </summary>
        public long ExpiredDateTick { get; set; }

        /// <summary>
        /// 获取或设置过期时间。
        /// </summary>
        public DateTimeOffset ExpiredDate { get; set; }

        /// <summary>
        /// 获取或设置签名内容。
        /// </summary>
        public byte[] Signature { get; set; }
    }
}
