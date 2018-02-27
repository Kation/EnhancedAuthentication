using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书哈希模式。
    /// </summary>
    public enum EnhancedAuthenticationCertificateHashMode : byte
    {
        /// <summary>
        /// MD5。
        /// </summary>
        MD5 = 1,
        /// <summary>
        /// SHA1。
        /// </summary>
        SHA1 = 2,
        /// <summary>
        /// SHA256。
        /// </summary>
        SHA256 = 3,
        /// <summary>
        /// SHA384。
        /// </summary>
        SHA384 = 4,
        /// <summary>
        /// SHA512。
        /// </summary>
        SHA512 = 5
    }
}
