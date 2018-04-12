using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书生成器。
    /// </summary>
    public class EnhancedAuthenticationCertificateGenerator : EnhancedAuthenticationCertificate
    {
        private EnhancedAuthenticationCertificateGenerator(TimeSpan period, int certId, EnhancedAuthenticationCertificateHashMode hashMode, byte[] extendedInformation)
            : base()
        {
            if (certId < 1)
                throw new ArgumentOutOfRangeException(nameof(certId), "证书Id不能小于1。");
            if (extendedInformation == null)
                throw new ArgumentNullException(nameof(extendedInformation));
            CertificateId = certId;
            ExpiredDate = DateTime.Now.Add(period);
            HasPrivateKey = true;
            HashMode = hashMode;
            ExtendedInformation = extendedInformation;
        }

        /// <summary>
        /// 生成证书。
        /// </summary>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="period">有效时间。</param>
        /// <param name="certId">证书Id。</param>
        /// <param name="hashMode">哈希模式。</param>
        /// <param name="extendedInformation">附加信息。</param>
        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, EnhancedAuthenticationCertificateHashMode hashMode, byte[] extendedInformation)
            : this(period, certId, hashMode, extendedInformation)
        {
            if (keySize < 1024)
                throw new ArgumentOutOfRangeException(nameof(keySize), "密钥长度不能小于1024。");
            if (keySize % 1024 != 0)
                throw new ArgumentException(nameof(keySize), "密钥长度必须为1024的倍数。");

            Cryptography = new RSACryptoServiceProvider(keySize);
            SignCertificate(this);
        }

        /// <summary>
        /// 生成证书。
        /// </summary>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="period">有效时间。</param>
        /// <param name="certId">证书Id。</param>
        /// <param name="extendedInformation">附加信息。</param>
        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, byte[] extendedInformation)
            : this(keySize, period, certId, EnhancedAuthenticationCertificateHashMode.SHA256, extendedInformation)
        { }

        /// <summary>
        /// 生成证书。
        /// </summary>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="period">有效时间。</param>
        /// <param name="certId">证书Id。</param>
        /// <param name="hashMode">哈希模式。</param>
        /// <param name="extendedInformation">附加信息。</param>
        /// <param name="root">给予签名的根证书。（需要私钥）</param>
        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, EnhancedAuthenticationCertificateHashMode hashMode, byte[] extendedInformation, EnhancedAuthenticationCertificate root)
            : this(period, certId, hashMode, extendedInformation)
        {
            if (keySize < 1024)
                throw new ArgumentOutOfRangeException(nameof(keySize), "密钥长度不能小于1024。");
            if (keySize % 1024 != 0)
                throw new ArgumentException(nameof(keySize), "密钥长度必须为1024的倍数。");
            if (root == null)
                throw new ArgumentNullException(nameof(root));

            Cryptography = new RSACryptoServiceProvider(keySize);
            root.SignCertificate(this);
        }

        /// <summary>
        /// 生成证书。
        /// </summary>
        /// <param name="keySize">密钥大小。</param>
        /// <param name="period">有效时间。</param>
        /// <param name="certId">证书Id。</param>
        /// <param name="extendedInformation">附加信息。</param>
        /// <param name="root">给予签名的根证书。（需要私钥）</param>
        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, byte[] extendedInformation, EnhancedAuthenticationCertificate root)
            : this(keySize, period, certId, EnhancedAuthenticationCertificateHashMode.SHA256, extendedInformation, root)
        { }
    }
}
