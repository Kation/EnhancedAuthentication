using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public class UserToken
    {
        public string UserId { get; set; }
        
        public string CurrentLevel { get; set; }

        public string MaximumLevel { get; set; }

        public long ExpiredDate { get; set; }
    }
}
