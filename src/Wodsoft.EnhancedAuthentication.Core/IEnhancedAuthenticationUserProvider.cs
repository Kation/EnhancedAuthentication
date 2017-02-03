using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public interface IEnhancedAuthenticationUserProvider
    {
        Task<IEnhancedAuthenticationUser> GetUserAsync();
        Task<IEnhancedAuthenticationUser> GetUserAsync(string userId);
        string GetSignInUrl(string returnUrl);        
        UserLevelStatus CheckLevel(IEnhancedAuthenticationUser user, string level);
    }
}
