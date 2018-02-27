using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 储存于内存的证书撤销管理器。
    /// </summary>
    public class MemoryRevokedCertificateManager : IRevokedCertificateManager
    {
        private List<int> _List;

        /// <summary>
        /// 实例化内存证书撤销管理器。
        /// </summary>
        public MemoryRevokedCertificateManager()
        {
            _List = new List<int>();
        }

        /// <summary>
        /// 获取上一次增加撤销证书时的日期。
        /// </summary>
        public DateTime? LastAddDate { get; private set; }

        /// <summary>
        /// 增加撤销证书。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        public void Add(int certId)
        {
            if (!_List.Contains(certId))
                _List.Add(certId);
            LastAddDate = DateTime.Now;
        }

        /// <summary>
        /// 批量增加撤销证书。
        /// </summary>
        /// <param name="certIds">证书Id。</param>
        public void AddRange(int[] certIds)
        {
            foreach (var id in certIds)
                if (!_List.Contains(id))
                    _List.Add(id);
            LastAddDate = DateTime.Now;
        }

        /// <summary>
        /// 清空撤销的证书。
        /// </summary>
        public void Clear()
        {
            _List.Clear();
            LastAddDate = null;
        }

        /// <summary>
        /// 证书是否已撤销。
        /// </summary>
        /// <param name="certId">证书Id。</param>
        /// <returns>返回证书是否已撤销。</returns>
        public bool Contains(int certId)
        {
            return _List.Contains(certId);
        }
    }
}
