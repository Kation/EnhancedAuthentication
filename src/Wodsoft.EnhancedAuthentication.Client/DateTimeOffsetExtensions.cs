using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.EnhancedAuthentication
{
#if NET40 || NET45
    /// <summary>
    /// 时间扩展方法类。
    /// </summary>
    public static class DateTimeOffsetExtensions
    {
        /// <summary>
        /// 返回自 1970 年 1 经过的毫秒数-01-01T00:00:00.000Z。
        /// </summary>
        /// <param name="dateTimeOffset">时间。</param>
        /// <returns></returns>
        public static long ToUnixTimeMilliseconds(this DateTimeOffset dateTimeOffset)
        {
            return (long)(dateTimeOffset - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalMilliseconds;
        }
    }
#endif
}
