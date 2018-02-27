using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书客户端。
    /// </summary>
    public class EnhancedAuthenticationCertificateClient : EnhancedAuthenticationHttpClient
    {

        /// <summary>
        /// 实例化增强认证证书客户端。
        /// </summary>
        /// <param name="serviceUri">服务地址。</param>
        /// <param name="provider"></param>
        public EnhancedAuthenticationCertificateClient(Uri serviceUri, EnhancedAuthenticationProvider provider)
            : base(serviceUri, provider)
        { }


        /// <summary>
        /// 请求根证书。
        /// </summary>
        /// <returns></returns>
        public async Task<EnhancedAuthenticationCertificate> RequestRootCertificate()
        {
#if NET40 || NET45
            ByteArrayContent content = new ByteArrayContent(new byte[0]);
#else
            ByteArrayContent content = new ByteArrayContent(Array.Empty<byte>());
#endif
            var certData = await HttpClient.GetByteArrayAsync("RootCertificate");
            Provider.RootCertificate = new EnhancedAuthenticationCertificate(certData);
            return Provider.RootCertificate;
        }

        /// <summary>
        /// 续签应用证书。
        /// </summary>
        /// <returns></returns>
        public async Task<EnhancedAuthenticationCertificate> RenewCertificate()
        {
            if (Provider.RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            if (Provider.AppCertificate == null)
                throw new NotSupportedException("当前不存在应用证书，不能续签证书。");
#if NET40 || NET45
            ByteArrayContent content = new ByteArrayContent(new byte[0]);
#else
            ByteArrayContent content = new ByteArrayContent(Array.Empty<byte>());
#endif
            var message = await RequestServiceAsync("RenewCertificate", content, "root.certificate");
            var certData = await message.ReadAsByteArrayAsync();
            message.Dispose();
            var cert = new EnhancedAuthenticationCertificate(certData);
            if (!cert.HasPrivateKey)
                throw new InvalidCastException("返回的证书不包含私钥。");
            if (!Provider.RootCertificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            Provider.AppCertificate = cert;
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
            if (Provider.RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            if (username == null)
                throw new ArgumentNullException(nameof(username));
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            Dictionary<string, string> data = new Dictionary<string, string>();
            data.Add("username", username);
            data.Add("password", password);
#if NET40
            foreach (var property in appInfo.GetType().GetProperties())
                data.Add(property.Name, property.GetValue(appInfo, null)?.ToString());
#else
            foreach (var property in appInfo.GetType().GetRuntimeProperties())
                data.Add(property.Name, property.GetValue(appInfo)?.ToString());
#endif

            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            var response = await HttpClient.PostAsync("RequestCertificate", content);            
            var certData = await response.EnsureSuccessStatusCode().Content.ReadAsByteArrayAsync();
            var cert = new EnhancedAuthenticationCertificate(certData);
            if (!cert.HasPrivateKey)
                throw new InvalidCastException("返回的证书不包含私钥。");
            if (!Provider.RootCertificate.VerifyCertificate(cert))
                throw new CryptographicException("证书验证失败。");
            Provider.AppCertificate = cert;
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
#if NET40
            foreach (var property in appInfo.GetType().GetProperties())
                data.Add(property.Name, property.GetValue(appInfo, null)?.ToString());
#else
            foreach (var property in appInfo.GetType().GetRuntimeProperties())
                data.Add(property.Name, property.GetValue(appInfo)?.ToString());
#endif

            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            var message = await HttpClient.PostAsync("ApplyCertificate", content);
            message.EnsureSuccessStatusCode();
            message.Dispose();
        }
        
        /// <summary>
        /// 更新证书吊销列表。
        /// </summary>
        /// <returns></returns>
        public async Task RefreshRevokedCertificate()
        {
            if (Provider.RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            DateTime? lastCheckDate = Provider.RevokedCertificateManager.LastAddDate;
            string url = "RevokedCertificate";
            if (lastCheckDate.HasValue)
                url += "?startDate=" + lastCheckDate.Value.ToString("yyyy-MM-dd HH:mm:ss");
            var list = await HttpClient.GetStringAsync(url);
            if (list.Length > 0)
                Provider.RevokedCertificateManager.AddRange(list.Split(',').Select(t => int.Parse(t)).ToArray());
        }        
    }
}
