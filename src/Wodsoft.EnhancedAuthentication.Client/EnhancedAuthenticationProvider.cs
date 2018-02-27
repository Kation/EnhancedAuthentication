using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证提供器。
    /// </summary>
    public class EnhancedAuthenticationProvider
    {
        /// <summary>
        /// 实例化增强认证客户端。
        /// </summary>
        /// <param name="rootCert">根证书。</param>
        /// <param name="appCert">应用证书。</param>
        /// <param name="revokedCertManager">证书撤销管理器。</param>
        public EnhancedAuthenticationProvider(EnhancedAuthenticationCertificate rootCert, EnhancedAuthenticationCertificate appCert, IRevokedCertificateManager revokedCertManager)
        {
            //if (rootCert == null)
            //    throw new ArgumentNullException(nameof(rootCert));
            //if (appCert == null)
            //    throw new ArgumentNullException(nameof(appCert));
            if (appCert != null && !appCert.HasPrivateKey)
                throw new ArgumentException("应用证书必须包含私钥。", nameof(appCert));
            if (revokedCertManager == null)
                throw new ArgumentNullException(nameof(revokedCertManager));
            RootCertificate = rootCert;
            AppCertificate = appCert;
            RevokedCertificateManager = revokedCertManager;
        }

        /// <summary>
        /// 实例化增强认证客户端。
        /// </summary>
        /// <param name="rootCert">根证书。</param>
        /// <param name="appCert">应用证书。</param>
        public EnhancedAuthenticationProvider(EnhancedAuthenticationCertificate rootCert, EnhancedAuthenticationCertificate appCert)
            : this(rootCert, appCert, new MemoryRevokedCertificateManager())
        { }

        /// <summary>
        /// 获取根证书。
        /// </summary>
        public EnhancedAuthenticationCertificate RootCertificate { get; set; }

        /// <summary>
        /// 获取应用证书。
        /// </summary>
        public EnhancedAuthenticationCertificate AppCertificate { get; set; }

        /// <summary>
        /// 获取证书撤销管理器。
        /// </summary>
        public IRevokedCertificateManager RevokedCertificateManager { get; private set; }

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
        /// 签名数据。
        /// </summary>
        /// <param name="data">要签名的数据。</param>
        /// <param name="purpose">用途。</param>
        /// <returns></returns>
        public byte[] SignData(byte[] data, byte[] purpose)
        {
            if (AppCertificate == null)
                throw new NotSupportedException("当前不存在应用证书，不能签名数据。");
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (purpose == null)
                return AppCertificate.Cryptography.SignData(data, AppCertificate.HashMode);
            else
                return AppCertificate.Cryptography.SignData(data.Concat(purpose).ToArray(), AppCertificate.HashMode);
        }

        /// <summary>
        /// 签名数据。
        /// </summary>
        /// <param name="data">要签名的数据。</param>
        /// <param name="purpose">用途。</param>
        /// <returns></returns>
        public byte[] SignData(byte[] data, string purpose)
        {
            if (purpose == null)
                throw new ArgumentNullException(nameof(purpose));
            return SignData(data, Encoding.UTF8.GetBytes(purpose));
        }

        /// <summary>
        /// 验证签名。
        /// </summary>
        /// <param name="cert">为数据签名的证书。</param>
        /// <param name="data">被签名的数据。</param>
        /// <param name="signature">签名数据。</param>
        /// <param name="purpose">用途。</param>
        /// <returns></returns>
        public bool VerifyData(EnhancedAuthenticationCertificate cert, byte[] data, byte[] signature, byte[] purpose)
        {
            if (RootCertificate == null)
                throw new NotSupportedException("当前不存在根证书，不能验证签名。");
            if (!RootCertificate.VerifyCertificate(cert))
                return false;
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            if (purpose == null)
                return cert.Cryptography.VerifyData(data, signature, cert.HashMode);
            else
                return cert.Cryptography.VerifyData(data.Concat(purpose).ToArray(), signature, cert.HashMode);
        }

        /// <summary>
        /// 验证签名。
        /// </summary>
        /// <param name="cert">为数据签名的证书。</param>
        /// <param name="data">被签名的数据。</param>
        /// <param name="signature">签名数据。</param>
        /// <param name="purpose">用途。</param>
        /// <returns></returns>
        public bool VerifyData(EnhancedAuthenticationCertificate cert, byte[] data, byte[] signature, string purpose)
        {
            if (purpose == null)
                throw new ArgumentNullException(nameof(purpose));
            return VerifyData(cert, data, signature, Encoding.UTF8.GetBytes(purpose));
        }
    }
}
