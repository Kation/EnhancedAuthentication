using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Wodsoft.EnhancedAuthentication.MvcCore
{
    /// <summary>
    /// Http上下文扩展方法。
    /// </summary>
    public static class HttpContextExtensions
    {
        /// <summary>
        /// 验证服务请求。
        /// </summary>
        /// <param name="httpContext">Http上下文。</param>
        /// <param name="purpose">用途，可以为空。</param>
        /// <returns>如果验证通过则返回应用证书。</returns>
        public static EnhancedAuthenticationCertificate VerifyServiceRequest(this HttpContext httpContext, string purpose = null)
        {
            if (!httpContext.Request.Headers.TryGetValue("certificate", out var certValue))
                throw new ArgumentNullException("certificate");
            if (!httpContext.Request.Headers.TryGetValue("signature", out var signatureValue))
                throw new ArgumentNullException("signature");
            if (!httpContext.Request.Headers.TryGetValue("expiredDate", out var expiredDateValue))
                throw new ArgumentNullException("expiredDate");
            var cert = new EnhancedAuthenticationCertificate(Convert.FromBase64String(certValue));
            var service = httpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            if (!service.Certificate.VerifyCertificate(cert))
                throw new UnauthorizedAccessException("验证证书失败。");
            if (service.CertificateProvider.CheckIsRevoked(cert.CertificateId).Result)
                throw new UnauthorizedAccessException("证书已撤销。");
            var signature = Convert.FromBase64String(signatureValue);
            long expiredDate = long.Parse(expiredDateValue);
            var data = BitConverter.GetBytes(expiredDate);
            if (purpose != null)
                data = data.Concat(Encoding.UTF8.GetBytes(purpose)).ToArray();
            if (!cert.Cryptography.VerifyData(data, signature, cert.HashMode))
                throw new UnauthorizedAccessException("验证签名失败。");
            if (DateTimeOffset.FromUnixTimeMilliseconds(expiredDate) < DateTime.Now)
                throw new UnauthorizedAccessException("安全信息已过期。");
            return cert;
        }
    }
}
