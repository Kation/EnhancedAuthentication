using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证Http客户端。
    /// </summary>
    public class EnhancedAuthenticationHttpClient : EnhancedAuthenticationClient, IDisposable
    {
        /// <summary>
        /// 实例化增强认证客户端。
        /// </summary>
        /// <param name="serviceUri">服务地址，以“/”结尾。</param>
        /// <param name="provider">增强认证提供器。</param>
        public EnhancedAuthenticationHttpClient(Uri serviceUri, EnhancedAuthenticationProvider provider) : base(provider)
        {
            ServiceUri = serviceUri ?? throw new ArgumentNullException(nameof(serviceUri));
            HttpClient = new HttpClient
            {
                BaseAddress = serviceUri
            };
            HttpClient.DefaultRequestHeaders.Connection.Add("keep-alive");
        }

        /// <summary>
        /// 获取Http客户端。
        /// </summary>
        protected HttpClient HttpClient { get; private set; }

        /// <summary>
        /// 获取服务地址。
        /// </summary>
        public Uri ServiceUri { get; private set; }

        /// <summary>
        /// 请求服务。
        /// </summary>
        /// <param name="serviceName">服务名。</param>
        /// <param name="content">请求内容。</param>
        /// <param name="purpose">用途，可以为空。</param>
        /// <returns>返回响应内容。</returns>
        public async Task<HttpContent> RequestServiceAsync(string serviceName, HttpContent content, string purpose)
        {
            if (_Disposed)
                throw new ObjectDisposedException("EnhancedAuthenticationClient");
            if (Provider.RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能续签证书。");
            if (Provider.AppCertificate == null)
                throw new NotSupportedException("当前不存在应用证书，不能续签证书。");
            SecureHttpContent(content, purpose);
            var message = await HttpClient.PostAsync(serviceName, content);
            return message.EnsureSuccessStatusCode().Content;
        }

        private string _CertificateHeader;
        /// <summary>
        /// 加密请求。
        /// </summary>
        /// <param name="content">请求内容。</param>
        /// <param name="purpose">用途。</param>
        protected virtual void SecureHttpContent(HttpContent content, string purpose)
        {
            if (_Disposed)
                throw new ObjectDisposedException("EnhancedAuthenticationClient");
            if (content == null)
                throw new ArgumentNullException(nameof(content));
            content.Headers.Add("certificate", _CertificateHeader ?? (_CertificateHeader = Convert.ToBase64String(Provider.AppCertificate.ExportCertificate(false))));
            var header = GetSecurityTicket(purpose);
            content.Headers.Add("expiredDate", header.ExpiredDateTick.ToString());
            content.Headers.Add("signature", Convert.ToBase64String(header.Signature));
        }

        private bool _Disposed;
        /// <summary>
        /// 释放资源。
        /// </summary>
        /// <param name="disposed">是否已释放。</param>
        protected override void Dispose(bool disposed)
        {
            base.Dispose(disposed);
            if (disposed)
                return;
            _Disposed = true;
            HttpClient.Dispose();
        }
    }
}
