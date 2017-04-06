using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class EnhancedAuthenticationExtensions
    {
        public static void AddEnhancedAuthenticationService<IUserProvider>(this IServiceCollection services, EnhancedAuthenticationCertificate rootCert, IEnhancedAuthenticationCertificateProvider certProvider)
            where IUserProvider : class, IEnhancedAuthenticationUserProvider
        {
            services.AddSingleton<EnhancedAuthenticationCertificate>(rootCert);
            services.AddSingleton<IEnhancedAuthenticationCertificateProvider>(certProvider);
            services.AddSingleton<EnhancedAuthenticationService>();
            services.AddScoped<IEnhancedAuthenticationUserProvider, IUserProvider>();
        }
    }
}
