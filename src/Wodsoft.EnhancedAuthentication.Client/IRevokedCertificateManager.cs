using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public interface IRevokedCertificateManager
    {
        bool Contains(int certId);

        void Add(int certId);

        void AddRange(int[] certIds);

        void Clear();

        DateTime? LastAddDate { get; }
    }
}
