using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Wodsoft.ComBoost.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Wodsoft.ComBoost.Data.Entity;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
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
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var eAuth = Configuration.GetSection("eAuth");
            var client = new EnhancedAuthenticationClient(eAuth.GetValue<Uri>("serviceUri"), null, null);
            client.RequestRootCertificate().Wait();
            client.RequestCertificate("admin", "admin", new AppInformation { AppId = "TestThirdPart" }).Wait();

            services.AddComBoostAuthentication<ComBoostAuthenticationSessionHandler>();
            services.AddEnhancedAuthenticationClient(client);
            services.AddSingleton<IEnhancedAuthenticationClientHandler, EnhancedAuthenticationClientHandler>();
            services.AddMemoryCache();
            services.AddSession();
            services.AddMvc();

            services.AddScoped<DbContext, DataContext>(serviceProvider =>
                new DataContext(new DbContextOptionsBuilder<DataContext>().UseInMemoryDatabase("Test")
                .Options));
            services.AddScoped<IDatabaseContext, DatabaseContext>();
            services.AddScoped<ISecurityProvider, ThirdPartSecurityProvider>();
            services.AddScoped<IAuthenticationProvider, ComBoostAuthenticationProvider>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
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

            app.UseAuthentication();

            app.UseEnhancedAuthenticationClient("/Account");
            
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
