using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public enum EnhancedAuthenticationCertificateHashMode : byte
    {
        MD5 = 1,
        SHA1 = 2,
        SHA256 = 3,
        SHA384 = 4,
        SHA512 = 5
    }
}
