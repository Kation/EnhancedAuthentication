using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart.Models
{
    public class Member : EntityBase, IPermission
    {
        public virtual string Username { get; set; }

        [NotMapped]
        public AccessLevel CurrentLevel { get; set; }

        [NotMapped]
        public AccessLevel MaximumLevel { get; set; }

        string IPermission.Identity { get { return Index.ToString(); } }

        string IPermission.Name
        {
            get
            {
                return Username;
            }
        }

        object[] IPermission.GetStaticRoles()
        {
            return new object[] { CurrentLevel };
        }

        bool IPermission.IsInRole(object role)
        {
            return false;
        }
    }
}
