using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Text;

namespace Wodsoft.EnhancedAuthentication
{
    public class EnhancedAuthenticationClient
    {
        private HttpClient _Client;

        public EnhancedAuthenticationClient(Uri serviceUri, EnhancedAuthenticationCertificate rootCert, EnhancedAuthenticationCertificate appCert, IRevokedCertificateManager revokedCertManager)
        {
            if (serviceUri == null)
                throw new ArgumentNullException(nameof(serviceUri));
            //if (rootCert == null)
            //    throw new ArgumentNullException(nameof(rootCert));
            //if (appCert == null)
            //    throw new ArgumentNullException(nameof(appCert));
            if (appCert != null && !appCert.HasPrivateKey)
                throw new ArgumentException("应用证书必须包含私钥。", nameof(appCert));
            if (revokedCertManager == null)
                throw new ArgumentNullException(nameof(revokedCertManager));
            ServiceUri = serviceUri;
            RootCertificate = rootCert;
            AppCertificate = appCert;
            _Client = new HttpClient();
            _Client.BaseAddress = serviceUri;
            RevokedCertificateManager = revokedCertManager;
        }

        public EnhancedAuthenticationClient(Uri serviceUri, EnhancedAuthenticationCertificate rootCert, EnhancedAuthenticationCertificate appCert)
            : this(serviceUri, rootCert, appCert, new MemoryRevokedCertificateManager())
        { }

        public Uri ServiceUri { get; private set; }

        public EnhancedAuthenticationCertificate RootCertificate { get; private set; }

        public EnhancedAuthenticationCertificate AppCertificate { get; private set; }

        public IRevokedCertificateManager RevokedCertificateManager { get; private set; }

        /// <summary>
        /// 请求根证书。
        /// </summary>
        /// <returns></returns>
        public async Task<EnhancedAuthenticationCertificate> RequestRootCertificate()
        {
            var certData = await _Client.GetByteArrayAsync("RootCertificate");
            RootCertificate = new EnhancedAuthenticationCertificate(certData);
            return RootCertificate;
        }

        /// <summary>
        /// 续签应用证书。
        /// </summary>
        /// <returns></returns>
        public async Task<EnhancedAuthenticationCertificate> RenewCertificate()
        {
            if (RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            if (AppCertificate == null)
                throw new NotSupportedException("当前不存在应用证书，不能续签证书。");
            var expiredDate = DateTime.Now.AddMinutes(5);
            var signature = AppCertificate.Cryptography.SignData(BitConverter.GetBytes(expiredDate.Ticks), AppCertificate.HashMode);
            Dictionary<string, string> data = new Dictionary<string, string>();
            data.Add("cert", Convert.ToBase64String(AppCertificate.ExportCertificate(false)));
            data.Add("expiredDate", expiredDate.Ticks.ToString());
            data.Add("signature", Convert.ToBase64String(signature));
            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            var message = await _Client.PostAsync("RenewCertificate", content);
            var certData = await message.EnsureSuccessStatusCode().Content.ReadAsByteArrayAsync();
            message.Dispose();
            var cert = new EnhancedAuthenticationCertificate(certData);
            if (!cert.HasPrivateKey)
                throw new InvalidCastException("返回的证书不包含私钥。");
            if (!RootCertificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            AppCertificate = cert;
            return cert;
        }

        /// <summary>
        /// 创建应用证书。
        /// </summary>
        /// <param name="username">管理用户名。</param>
        /// <param name="password">管理密码。</param>
        /// <param name="appInfo">应用信息。</param>
        /// <returns></returns>
        public async Task<EnhancedAuthenticationCertificate> RequestCertificate(string username, string password, AppInformation appInfo)
        {
            if (RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            if (username == null)
                throw new ArgumentNullException(nameof(username));
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            Dictionary<string, string> data = new Dictionary<string, string>();
            data.Add("username", username);
            data.Add("password", password);
            foreach (var property in appInfo.GetType().GetRuntimeProperties())
                data.Add(property.Name, property.GetValue(appInfo)?.ToString());

            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            var message = await _Client.PostAsync("RequestCertificate", content);
            var certData = await message.EnsureSuccessStatusCode().Content.ReadAsByteArrayAsync();
            message.Dispose();
            var cert = new EnhancedAuthenticationCertificate(certData);
            if (!cert.HasPrivateKey)
                throw new InvalidCastException("返回的证书不包含私钥。");
            if (!RootCertificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            AppCertificate = cert;
            return cert;
        }

        /// <summary>
        /// 申请应用证书。
        /// </summary>
        /// <param name="appInfo">应用信息。</param>
        /// <param name="callbackUrl">回调地址。</param>
        /// <returns></returns>
        public async Task ApplyCertificate(AppInformation appInfo, string callbackUrl)
        {
            Dictionary<string, string> data = new Dictionary<string, string>();
            data.Add("callback", callbackUrl);
            foreach (var property in appInfo.GetType().GetRuntimeProperties())
                data.Add(property.Name, property.GetValue(appInfo)?.ToString());

            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            var message = await _Client.PostAsync("ApplyCertificate", content);
            message.EnsureSuccessStatusCode();
            message.Dispose();
        }

        /// <summary>
        /// 应用应用证书。
        /// </summary>
        /// <param name="cert">应用证书。</param>
        /// <returns></returns>
        public void ApplyCertificate(EnhancedAuthenticationCertificate cert)
        {
            if (RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能应用应用证书。");
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));
            if (!cert.HasPrivateKey)
                throw new InvalidCastException("返回的证书不包含私钥。");
            if (!RootCertificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            AppCertificate = cert;
        }

        /// <summary>
        /// 更新证书吊销列表。
        /// </summary>
        /// <returns></returns>
        public async Task RefreshRevokedCertificate()
        {
            if (RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            DateTime? lastCheckDate = RevokedCertificateManager.LastAddDate;
            string url = "RevokedCertificate";
            if (lastCheckDate.HasValue)
                url += "?startDate=" + lastCheckDate.Value.ToString("yyyy-MM-dd HH:mm:ss");
            var list = await _Client.GetStringAsync(url);
            if (list.Length > 0)
                RevokedCertificateManager.AddRange(list.Split(',').Select(t => int.Parse(t)).ToArray());
        }

        /// <summary>
        /// 获取授权地址。
        /// </summary>
        /// <param name="requestLevel">请求级别。</param>
        /// <param name="returnUrl">回调地址。</param>
        /// <returns></returns>
        public Uri GetAuthorizeUrl(string requestLevel, string returnUrl)
        {
            if (AppCertificate == null)
                throw new NotSupportedException("当前不存在应用证书，不能获取授权地址证书。");
            string cert = Convert.ToBase64String(AppCertificate.ExportCertificate(false));
            return new Uri(_Client.BaseAddress, "Authorize?cert=" + Uri.EscapeDataString(cert) + "&requestLevel=" + requestLevel + "&returnUrl=" + Uri.EscapeDataString(Convert.ToBase64String(Encoding.ASCII.GetBytes(returnUrl))));
        }

        public async Task<string> RequestService(string serviceName, object arguments)
        {

        }
    }
}
