using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class EnhancedAuthenticationClientExtensions
    {
        public static void AddEnhancedAuthenticationClient(this IServiceCollection serviceCollection, EnhancedAuthenticationClient client)
        {
            serviceCollection.AddSingleton<EnhancedAuthenticationClient>(client);
        }
    }
}

namespace Microsoft.AspNetCore.Builder
{
    public static class EnhancedAuthenticationClientExtensions
    {
        public static void UseEnhancedAuthenticationClient(this IApplicationBuilder app, string path)
        {
            //var client = app.ApplicationServices.GetRequiredService<EnhancedAuthenticationClient>();
            app.UseMiddleware<EnhancedAuthenticationClientMiddleware>(new PathString(path));
        }
    }
}