using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证客户端基类。
    /// </summary>
    public abstract class EnhancedAuthenticationClient : IDisposable
    {
        /// <summary>
        /// 实例化增强认证客户端。
        /// </summary>
        /// <param name="provider">增强认证提供器。</param>
        public EnhancedAuthenticationClient(EnhancedAuthenticationProvider provider)
        {
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _SecureHeader = new ConcurrentDictionary<string, EnhancedAuthenticationSecurityTicket>();
        }
        
        /// <summary>
        /// 获取增强认证提供器。
        /// </summary>
        public EnhancedAuthenticationProvider Provider { get; private set; }
        
        private ConcurrentDictionary<string, EnhancedAuthenticationSecurityTicket> _SecureHeader;        
        private EnhancedAuthenticationSecurityTicket CreateSecurityTicket(string purpose)
        {
            var expiredDate = DateTimeOffset.Now.AddMinutes(10);
            var expiredTick = expiredDate.ToUnixTimeMilliseconds();
            var expiredDateBytes = BitConverter.GetBytes(expiredTick);
            if (purpose != null)
                expiredDateBytes = expiredDateBytes.Concat(Encoding.UTF8.GetBytes(purpose)).ToArray();
            var signature = Provider.AppCertificate.Cryptography.SignData(expiredDateBytes, Provider.AppCertificate.HashMode);
            return new EnhancedAuthenticationSecurityTicket
            {
                ExpiredDateTick = expiredTick,
                ExpiredDate = expiredDate,
                Signature = signature
            };
        }

        /// <summary>
        /// 获取安全票据。
        /// </summary>
        /// <param name="purpose">用途，可以为空。</param>
        /// <returns>返回安全票据。</returns>
        protected virtual EnhancedAuthenticationSecurityTicket GetSecurityTicket(string purpose)
        {
            if (_Disposed)
                throw new ObjectDisposedException("EnhancedAuthenticationClient");
            var ticket = _SecureHeader.GetOrAdd(purpose, p => CreateSecurityTicket(p));
            if (ticket.ExpiredDate < DateTime.Now)
                _SecureHeader[purpose] = ticket = CreateSecurityTicket(purpose);
            return ticket;
        }

        private bool _Disposed;
        /// <summary>
        /// 释放资源。
        /// </summary>
        public void Dispose()
        {
            Dispose(_Disposed);
        }

        /// <summary>
        /// 释放资源。
        /// </summary>
        /// <param name="disposed">是否已释放。</param>
        protected virtual void Dispose(bool disposed)
        {
            if (_Disposed)
                return;
            _Disposed = true;
            _SecureHeader.Clear();
            _SecureHeader = null;
        }
    }
}
