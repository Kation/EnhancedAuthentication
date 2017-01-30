using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    public class EnhancedAuthenticationCertificateGenerator : EnhancedAuthenticationCertificate
    {
        private EnhancedAuthenticationCertificateGenerator(TimeSpan period, int certId, EnhancedAuthenticationCertificateHashMode hashMode, byte[] extendedInformation)
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

        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, byte[] extendedInformation)
            : this(keySize, period, certId, EnhancedAuthenticationCertificateHashMode.SHA1, extendedInformation)
        { }

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

        public EnhancedAuthenticationCertificateGenerator(int keySize, TimeSpan period, int certId, byte[] extendedInformation, EnhancedAuthenticationCertificate root)
            : this(keySize, period, certId, EnhancedAuthenticationCertificateHashMode.SHA1, extendedInformation, root)
        { }
    }
}
