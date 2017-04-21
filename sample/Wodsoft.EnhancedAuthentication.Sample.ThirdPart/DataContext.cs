using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication.Sample.ThirdPart.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions options) : base(options) { }

        public DataContext() { }

        public DbSet<Member> Member { get; set; }
    }
}
