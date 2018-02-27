using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 证书撤销管理器。
    /// </summary>
    public interface IRevokedCertificateManager
    {
        /// <summary>
        /// 证书是否已撤销。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        /// <returns>返回证书是否已撤销。</returns>
        bool Contains(int certId);

        /// <summary>
        /// 增加撤销证书。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        void Add(int certId);

        /// <summary>
        /// 批量增加撤销证书。
        /// </summary>
        /// <param name="certIds">证书Id。</param>
        void AddRange(int[] certIds);

        /// <summary>
        /// 清空撤销的证书。
        /// </summary>
        void Clear();

        /// <summary>
        /// 获取上一次增加撤销证书时的日期。
        /// </summary>
        DateTime? LastAddDate { get; }
    }
}
