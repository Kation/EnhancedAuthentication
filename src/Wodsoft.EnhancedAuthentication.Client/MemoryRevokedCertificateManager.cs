using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public class MemoryRevokedCertificateManager : IRevokedCertificateManager
    {
        private List<int> _List;

        public MemoryRevokedCertificateManager()
        {
            _List = new List<int>();
        }

        public DateTime? LastAddDate { get; private set; }

        public void Add(int certId)
        {
            if (!_List.Contains(certId))
                _List.Add(certId);
            LastAddDate = DateTime.Now;
        }

        public void AddRange(int[] certIds)
        {
            foreach (var id in certIds)
                if (!_List.Contains(id))
                    _List.Add(id);
            LastAddDate = DateTime.Now;
        }

        public void Clear()
        {
            _List.Clear();
            LastAddDate = null;
        }

        public bool Contains(int certId)
        {
            return _List.Contains(certId);
        }
    }
}
