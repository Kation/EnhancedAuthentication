using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication
{
    /// <summary>
    /// 增强认证证书。
    /// </summary>
    public class EnhancedAuthenticationCertificate
    {
        /// <summary>
        /// 派生类无参构造函数。
        /// </summary>
        protected EnhancedAuthenticationCertificate() { }

        /// <summary>
        /// 实例化增强认证证书。
        /// </summary>
        /// <param name="raw">证书原始数据。</param>
        public EnhancedAuthenticationCertificate(byte[] raw)
        {
            if (raw == null)
                throw new ArgumentNullException(nameof(raw));
            if (raw.Length < 276)
                throw new ArgumentException(nameof(raw), "证书数据错误。");
            var offset = 0;
            CertificateId = BitConverter.ToInt32(raw, offset);
            offset += 4;
            HasPrivateKey = CertificateId < 0;
            if (HasPrivateKey)
            {
                CertificateId = -CertificateId;
                if (raw.Length < 724)
                    throw new ArgumentException(nameof(raw), "证书数据错误。");
            }
            ExpiredDate = new DateTime(BitConverter.ToInt64(raw, offset));
            offset += 8;
            var keySize = BitConverter.ToInt32(raw, offset);
            offset += 4;
#if NET40 || NET45
            Cryptography = new RSACryptoServiceProvider();
#else
            Cryptography = new RSACng();
#endif
            try
            {
                if (HasPrivateKey)
                    Cryptography.ImportPrivateKey(keySize, raw, 16);
                else
                    Cryptography.ImportPublicKey(keySize, raw, 16);
            }
            catch
            {
                throw new ArgumentException(nameof(raw), "证书数据错误。");
            }
            var max = keySize / 8;
            var min = max / 2;
            if (HasPrivateKey)
                offset += max * 2 + min * 5 + 3;
            else
                offset += max + 3;
            HashMode = (EnhancedAuthenticationCertificateHashMode)raw[offset];
            offset++;
            Signature = raw.Skip(offset).Take(max).ToArray();
            offset += max;
            ExtendedInformation = raw.Skip(offset).ToArray();
            if (HasPrivateKey)
                _PrivateRaw = raw.ToArray();
            else
                _PublicRaw = raw.ToArray();
        }

        private byte[] _PrivateRaw, _PublicRaw;

        /// <summary>
        /// 获取证书Id。
        /// </summary>
        public int CertificateId { get; protected set; }

        /// <summary>
        /// 获取证书附加信息。
        /// </summary>
        public byte[] ExtendedInformation { get; protected set; }

        /// <summary>
        /// 获取证书是否拥有私钥。
        /// </summary>
        public bool HasPrivateKey { get; protected set; }

        /// <summary>
        /// 获取证书RSA加密类。
        /// </summary>
        public RSA Cryptography { get; protected set; }

        /// <summary>
        /// 获取证书过期时间。
        /// </summary>
        public DateTimeOffset ExpiredDate { get; protected set; }

        /// <summary>
        /// 获取证书签名。
        /// </summary>
        public byte[] Signature { get; protected set; }

        /// <summary>
        /// 获取证书哈希模式。
        /// </summary>
        public EnhancedAuthenticationCertificateHashMode HashMode { get; protected set; }

        /// <summary>
        /// 导出证书数据。
        /// </summary>
        /// <param name="includePrivateKey">是否包含私钥。</param>
        /// <exception cref="InvalidOperationException">此证书不包含私钥时，includePrivateKey不能为true。</exception>
        /// <returns>返回证书数据。</returns>
        public byte[] ExportCertificate(bool includePrivateKey)
        {
            if (includePrivateKey && !HasPrivateKey)
                throw new InvalidOperationException("不支持导出没有私钥的证书。");
            if (includePrivateKey && _PrivateRaw != null)
                return _PrivateRaw;
            if (!includePrivateKey && _PublicRaw != null)
                return _PublicRaw;

            List<byte> data = new List<byte>();
            if (includePrivateKey)
                data.AddRange(BitConverter.GetBytes(-CertificateId));
            else
                data.AddRange(BitConverter.GetBytes(CertificateId));
            data.AddRange(BitConverter.GetBytes(ExpiredDate.Ticks));
            data.AddRange(BitConverter.GetBytes(Cryptography.KeySize));
            if (includePrivateKey)
                data.AddRange(Cryptography.ExportPrivateKey());
            else
                data.AddRange(Cryptography.ExportPublicKey());
            data.Add((byte)HashMode);
            data.AddRange(Signature);
            data.AddRange(ExtendedInformation);
            var raw = data.ToArray();

            if (includePrivateKey)
                _PrivateRaw = raw;
            else
                _PublicRaw = raw;
            return raw;
        }

        /// <summary>
        /// 验证证书。
        /// </summary>
        /// <param name="certificate">要验证的证书。</param>
        /// <returns>返回是否验证通过。</returns>
        public bool VerifyCertificate(EnhancedAuthenticationCertificate certificate)
        {
            if (certificate.ExpiredDate < DateTime.Now)
                return false;
            var data = BitConverter.GetBytes(certificate.ExpiredDate.Ticks).Concat(BitConverter.GetBytes(certificate.CertificateId)).Concat(certificate.Cryptography.ExportPublicKey()).Concat(ExtendedInformation).ToArray();
            return Cryptography.VerifyData(data, certificate.Signature, certificate.HashMode);
        }

        /// <summary>
        /// 签名证书。
        /// </summary>
        /// <param name="certificate">要被签名的证书。</param>
        /// <exception cref="InvalidOperationException">此证书不包含私钥时，不能给其它证书签名。</exception>
        public void SignCertificate(EnhancedAuthenticationCertificate certificate)
        {
            if (!HasPrivateKey)
                throw new InvalidOperationException("没有私钥的证书不支持颁发签名。");
            var data = BitConverter.GetBytes(certificate.ExpiredDate.Ticks).Concat(BitConverter.GetBytes(certificate.CertificateId)).Concat(certificate.Cryptography.ExportPublicKey()).Concat(ExtendedInformation).ToArray();
            certificate.Signature = Cryptography.SignData(data, certificate.HashMode);
        }
    }
}
