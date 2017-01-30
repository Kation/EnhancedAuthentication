using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public interface IUserProvider
    {
        Task<IUser> GetUserAsync();
        Task<IUser> GetUserAsync(string userId);
        Task<object> GetUserInfo(string userId);

        string GetSignInUrl(string returnUrl);
        
        UserLevelStatus CheckLevel(IUser user, string level);
    }
}
