using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public interface IEnhancedAuthenticationUser
    {
        string UserId { get; }

        string CurrentLevel { get; }

        string MaximumLevel { get; }
    }
}
