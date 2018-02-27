using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证服务。
    /// </summary>
    public class EnhancedAuthenticationService
    {
        /// <summary>
        /// 获取用户提供器。
        /// </summary>
        public IEnhancedAuthenticationUserProvider UserProvider { get; private set; }

        /// <summary>
        /// 获取证书提供器。
        /// </summary>
        public IEnhancedAuthenticationCertificateProvider CertificateProvider { get; private set; }

        /// <summary>
        /// 获取根证书。
        /// </summary>
        public EnhancedAuthenticationCertificate Certificate { get; private set; }

        /// <summary>
        /// 实例化增强认证服务。
        /// </summary>
        /// <param name="certificate">根证书。</param>
        /// <param name="userProvider">用户提供器。</param>
        /// <param name="certificateProvider">证书提供器。</param>
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

        /// <summary>
        /// 异步创建证书。
        /// </summary>
        /// <param name="appInfo">应用信息。</param>
        /// <returns>返回应用证书。</returns>
        public async Task<EnhancedAuthenticationCertificate> CreateCertificateAsync(AppInformation appInfo)
        {
            if (appInfo == null)
                throw new ArgumentNullException(nameof(appInfo));
            int certId = await CertificateProvider.NewIdAsync();
            byte[] appInfoData = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(appInfo));
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

        /// <summary>
        /// 异步续签应用证书。
        /// </summary>
        /// <param name="oldCert">旧应用证书。</param>
        /// <returns>返回新应用证书。</returns>
        public async Task<EnhancedAuthenticationCertificate> RenewCertificateAsync(EnhancedAuthenticationCertificate oldCert)
        {
            if (oldCert == null)
                throw new ArgumentNullException(nameof(oldCert));
            if (!Certificate.VerifyCertificate(oldCert) || await CertificateProvider.CheckIsRevoked(Certificate.CertificateId))
                throw new CryptographicException("证书验证失败。");
            var newId = await CertificateProvider.NewIdAsync();
            await CertificateProvider.RevokeAsync(oldCert.CertificateId, oldCert.ExpiredDate.ToLocalTime().DateTime);
            EnhancedAuthenticationCertificateGenerator cert = new EnhancedAuthenticationCertificateGenerator(
                CertificateProvider.KeySize,
                CertificateProvider.Period,
                newId,
                CertificateProvider.HashMode,
                oldCert.ExtendedInformation,
                Certificate);
            return cert;
        }

        /// <summary>
        /// 异步撤销应用证书。
        /// </summary>
        /// <param name="cert">应用证书。</param>
        /// <returns></returns>
        public async Task GetRevokeCertificateAsync(EnhancedAuthenticationCertificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));
            if (!Certificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            await CertificateProvider.RevokeAsync(cert.CertificateId, cert.ExpiredDate.ToLocalTime().DateTime);
        }

        /// <summary>
        /// 获取撤销的证书列表。
        /// </summary>
        /// <param name="startDate">起始撤销时间。</param>
        /// <returns>返回被撤销的证书Id数组。</returns>
        public Task<int[]> GetRevokedCertificateListAsync(DateTime? startDate)
        {
            return CertificateProvider.GetRevokedListAsync(startDate);
        }

        /// <summary>
        /// 获取用户令牌。
        /// </summary>
        /// <param name="cert">应用证书。</param>
        /// <param name="user">用户。</param>
        /// <param name="level">授权等级。</param>
        /// <param name="rnd">随机码。</param>
        /// <param name="signature">签名。</param>
        /// <returns>返回令牌Base64编码数据。</returns>
        public string GetUserToken(EnhancedAuthenticationCertificate cert, IEnhancedAuthenticationUser user, byte level, byte[] rnd, out string signature)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));
            UserToken userToken = new UserToken();
            userToken.UserId = user.UserId;
            userToken.CurrentLevel = level;
            userToken.MaximumLevel = user.MaximumLevel;
            var data = Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(userToken)).ToArray();
            signature = Convert.ToBase64String(Certificate.Cryptography.SignData(data.Concat(rnd).ToArray(), Certificate.HashMode));
            data = cert.Cryptography.Encrypt(data);
            return Convert.ToBase64String(data);
        }
    }
}
