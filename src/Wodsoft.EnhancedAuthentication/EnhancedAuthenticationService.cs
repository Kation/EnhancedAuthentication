using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Wodsoft.EnhancedAuthentication
{
    public class EnhancedAuthenticationService
    {
        public IEnhancedAuthenticationUserProvider UserProvider { get; private set; }

        public IEnhancedAuthenticationCertificateProvider CertificateProvider { get; private set; }

        public EnhancedAuthenticationCertificate Certificate { get; private set; }

        public EnhancedAuthenticationService(EnhancedAuthenticationCertificate certificate, IEnhancedAuthenticationUserProvider userProvider, IEnhancedAuthenticationCertificateProvider certificateProvider)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (userProvider == null)
                throw new ArgumentNullException(nameof(userProvider));
            if (certificateProvider == null)
                throw new ArgumentNullException(nameof(certificateProvider));
            if (!certificate.HasPrivateKey)
                throw new ArgumentException(nameof(certificate), "传入的证书必须有私钥。");
            Certificate = certificate;
            UserProvider = userProvider;
            CertificateProvider = certificateProvider;
        }

        public async Task<EnhancedAuthenticationCertificate> CreateCertificateAsync(AppInformation appInfo)
        {
            if (appInfo == null)
                throw new ArgumentNullException(nameof(appInfo));
            int certId = await CertificateProvider.NewIdAsync();
            byte[] appInfoData = Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(appInfo));
            EnhancedAuthenticationCertificateGenerator cert = new EnhancedAuthenticationCertificateGenerator(
                CertificateProvider.KeySize,
                CertificateProvider.Period,
                certId,
                CertificateProvider.HashMode,
                appInfoData,
                Certificate);
            await CertificateProvider.NewCertificateAsync(cert);
            return cert;
        }

        public async Task<EnhancedAuthenticationCertificate> RenewCertificate(EnhancedAuthenticationCertificate oldCert)
        {
            if (oldCert == null)
                throw new ArgumentNullException(nameof(oldCert));
            if (!Certificate.VerifyCertificate(oldCert) || await CertificateProvider.CheckIsRevoked(Certificate.CertificateId))
                throw new CryptographicException("证书验证失败。");
            var newId = await CertificateProvider.NewIdAsync();
            await CertificateProvider.RevokeAsync(oldCert.CertificateId, oldCert.ExpiredDate);
            EnhancedAuthenticationCertificateGenerator cert = new EnhancedAuthenticationCertificateGenerator(
                CertificateProvider.KeySize,
                CertificateProvider.Period,
                newId,
                CertificateProvider.HashMode,
                oldCert.ExtendedInformation,
                Certificate);
            return cert;
        }

        public async Task RevokeCertificate(EnhancedAuthenticationCertificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));
            if (!Certificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            await CertificateProvider.RevokeAsync(cert.CertificateId, cert.ExpiredDate);
        }

        public Task<int[]> RevokedCertificateList(DateTime? startDate)
        {
            return CertificateProvider.GetRevokedListAsync(startDate);
        }

        public string GetUserToken(EnhancedAuthenticationCertificate cert, IEnhancedAuthenticationUser user, byte level, out string signature)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));
            UserToken userToken = new UserToken();
            userToken.UserId = user.UserId;
            userToken.CurrentLevel = level;
            userToken.MaximumLevel = user.MaximumLevel;
            userToken.ExpiredDate = DateTime.Now.AddMinutes(5).Ticks;
            var data = Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(userToken));
            signature = Convert.ToBase64String(Certificate.Cryptography.SignData(data, Certificate.HashMode));
            data = cert.Cryptography.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(data);
        }
    }
}
