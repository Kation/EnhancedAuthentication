using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Wodsoft.ComBoost.Mvc;
using Microsoft.EntityFrameworkCore;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.ComBoost.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Wodsoft.ComBoost;
using Wodsoft.ComBoost.Data;
using Wodsoft.EnhancedAuthentication.Sample.ServiceHost.Models;
using Microsoft.AspNetCore.Routing;
using System.IO;
using Microsoft.AspNetCore.Mvc.Internal;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            root = env.ContentRootPath;
            Configuration = builder.Build();
            _RootCert = new EnhancedAuthenticationCertificate(File.ReadAllBytes(root + Path.DirectorySeparatorChar + "cert.key"));
        }

        private EnhancedAuthenticationCertificate _RootCert;
        private string root;
        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMemoryCache();
            services.AddSession();
            services.AddMvc(options =>
            {
                options.AddComBoostMvcOptions();
            });
            services.AddComBoostMvcAuthentication();

            services.AddScoped<DbContext, DataContext>(serviceProvider =>
                new DataContext(new DbContextOptionsBuilder<DataContext>().UseInMemoryDatabase()
                .Options.WithExtension(new ComBoostOptionExtension())));
            services.AddScoped<IDatabaseContext, DatabaseContext>();
            services.AddScoped<ISecurityProvider, SecurityProvider>();
            services.AddScoped<IAuthenticationProvider, ComBoostAuthenticationProvider>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();

            services.AddEnhancedAuthenticationService<EnhancedAuthenticationUserProvider>(_RootCert, new EnhancedAuthenticationCertificateProvider(root));
            services.AddSingleton<IDomainServiceProvider, DomainProvider>(t =>
            {
                var provider = new DomainProvider(t);
                provider.AddGenericDefinitionExtension(typeof(EntityDomainService<>), typeof(EntitySearchExtension<>));
                provider.AddGenericDefinitionExtension(typeof(EntityDomainService<>), typeof(EntityPagerExtension<>));
                provider.AddGenericDefinitionExtension(typeof(EntityDomainService<>), typeof(EntityPasswordExtension<>));
                return provider;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseSession();
            
            app.UseComBoostMvc(routes =>
            {
                routes.MapAreaRoute(
                    name: "Admin",
                    areaName: "Admin",
                    template: "Admin/{controller=Home}/{action=Index}/{id?}",
                    defaults: null,
                    constraints: null,
                    dataTokens: new
                    {
                        authArea = "Admin",
                        permissionType = typeof(Admin),
                        timeout = TimeSpan.FromMinutes(15),
                        loginPath = "/Admin/Account/SignIn"
                    });
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}",
                    defaults: null,
                    constraints: null,
                    dataTokens: new
                    {
                        permissionType = typeof(Member),
                        timeout = TimeSpan.FromDays(30),
                        loginPath = "/Account/SignIn"
                    });
            });
        }
    }
}
