using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Wodsoft.EnhancedAuthentication;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 增强认证扩展方法。
    /// </summary>
    public static class EnhancedAuthenticationExtensions
    {
        /// <summary>
        /// 添加增强认证服务。
        /// </summary>
        /// <typeparam name="IUserProvider">用户提供器类型。</typeparam>
        /// <param name="services">服务集合。</param>
        /// <param name="rootCert">根证书。</param>
        /// <param name="certProvider">证书提供器。</param>
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
