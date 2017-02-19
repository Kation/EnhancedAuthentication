using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data.Entity;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models
{
    [EntityAuthentication(AllowAnonymous = false,
        AddRolesRequired = new object[] { "superAdmin" },
        EditRolesRequired = new object[] { "superAdmin" },
        RemoveRolesRequired = new object[] { "superAdmin" },
        ViewRolesRequired = new object[] { "admin" })]
    public class Admin : UserBase, IPermission
    {
        [Required]
        public virtual string Username { get; set; }

        [Required]
        [Hide]
        public virtual bool IsSystem { get; set; }

        string IPermission.Identity { get { return Index.ToString(); } }

        string IPermission.Name { get { return Username; } }

        object[] IPermission.GetStaticRoles() { return new object[0]; }

        bool IPermission.IsInRole(object role)
        {
            if (role is string)
            {
                string roleString = (string)role;
                return roleString == "admin" || (roleString == "superAdmin" && IsSystem);
            }
            return false;
        }
    }
}
