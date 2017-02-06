using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions options) : base(options) { }

        public DataContext() { }

        public DbSet<Admin> Admin { get; set; }

        public DbSet<Member> Member { get; set; }
    }
}
