using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public interface IEnhancedAuthenticationCertificateProvider
    {
        Task<int> NewIdAsync();

        TimeSpan Period { get; }

        int KeySize { get; }

        Task<int[]> GetRevokedListAsync(DateTime? startDate);

        Task RevokeAsync(int certId, DateTime expiredDate);

        Task<bool> CheckIsRevoked(int certId);
    }
}
