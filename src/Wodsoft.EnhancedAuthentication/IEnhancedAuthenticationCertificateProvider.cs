using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书提供器。
    /// </summary>
    public interface IEnhancedAuthenticationCertificateProvider
    {
        /// <summary>
        /// 异步获取新证书Id。
        /// </summary>
        /// <returns>返回新证书Id。</returns>
        Task<int> NewIdAsync();

        /// <summary>
        /// 获取默认证书有效期。
        /// </summary>
        TimeSpan Period { get; }

        /// <summary>
        /// 获取默认证书密钥大小。
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// 获取默认证书哈希模式。
        /// </summary>
        EnhancedAuthenticationCertificateHashMode HashMode { get; }

        /// <summary>
        /// 异步获取撤销证书Id。
        /// </summary>
        /// <param name="startDate">起始撤销时间。</param>
        /// <returns>返回撤销证书Id数组。</returns>
        Task<int[]> GetRevokedListAsync(DateTime? startDate);

        /// <summary>
        /// 异步撤销证书。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        /// <param name="expiredDate">证书过期时间。</param>
        /// <returns></returns>
        Task RevokeAsync(int certId, DateTime expiredDate);

        /// <summary>
        /// 检查证书是否已撤销。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        /// <returns>返回是否已撤销。</returns>
        Task<bool> CheckIsRevoked(int certId);

        /// <summary>
        /// 新证书生成。
        /// </summary>
        /// <param name="cert">新证书。</param>
        /// <returns></returns>
        Task NewCertificateAsync(EnhancedAuthenticationCertificate cert);
    }
}
