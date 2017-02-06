using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models
{
    public class Member : UserBase, IPermission
    {
        public virtual string Username { get; set; }

        public virtual AccessLevel Level { get; set; }

        string IPermission.Identity { get { return Index.ToString(); } }

        string IPermission.Name { get { return Username; } }

        object[] IPermission.GetStaticRoles()
        {
            return new object[0];
        }

        bool IPermission.IsInRole(object role)
        {
            return true;
        }
    }
}
