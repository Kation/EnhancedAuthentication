using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models
{
    public class EAuthUser : IEnhancedAuthenticationUser
    {
        public string CurrentLevel { get; set; }

        public string MaximumLevel { get; set; }

        public string UserId { get; set; }
    }
}
