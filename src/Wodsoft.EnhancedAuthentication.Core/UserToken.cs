using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public class UserToken
    {
        public string UserId { get; set; }

        public byte CurrentLevel { get; set; }

        public byte MaximumLevel { get; set; }
    }
}
