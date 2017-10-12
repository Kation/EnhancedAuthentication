using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.EnhancedAuthentication.MvcCore
{
    public static class HttpContextExtensions
    {
        public static EnhancedAuthenticationCertificate VerifyServiceRequest(this HttpContext httpContext)
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
            var signature = Convert.FromBase64String(signatureValue);
            long expiredDate = long.Parse(expiredDateValue);
            if (!cert.Cryptography.VerifyData(BitConverter.GetBytes(expiredDate), signature, cert.HashMode))
                throw new UnauthorizedAccessException("验证签名失败。");
            if (new DateTime(expiredDate) < DateTime.Now)
                throw new UnauthorizedAccessException("安全信息已过期。");
            return cert;
        }
    }
}
