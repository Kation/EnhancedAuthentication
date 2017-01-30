using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Wodsoft.EnhancedAuthentication.UnitTest
{

    public class RSATest
    {
        [Fact]
        public void CertificateTest()
        {
            EnhancedAuthenticationCertificateGenerator rootGenerator = new EnhancedAuthenticationCertificateGenerator(2048, TimeSpan.FromDays(365 * 18), 1, new byte[0]);
            var publicCertData = rootGenerator.ExportCertificate(false);
            var privateCertData = rootGenerator.ExportCertificate(true);

            var rootPublicCert = new EnhancedAuthenticationCertificate(publicCertData);
            var rootPrivateCert = new EnhancedAuthenticationCertificate(privateCertData);

            Assert.True(rootPublicCert.VerifyCertificate(rootPublicCert));

            EnhancedAuthenticationCertificateGenerator appGenerator = new EnhancedAuthenticationCertificateGenerator(2048, TimeSpan.FromDays(365 * 3), 2, new byte[0], rootPrivateCert);
            Assert.True(rootPublicCert.VerifyCertificate(appGenerator));

            var appPublicCertData = appGenerator.ExportCertificate(false);
            var appPublicCert = new EnhancedAuthenticationCertificate(appPublicCertData);
            Assert.True(rootPublicCert.VerifyCertificate(appPublicCert));

            Assert.True(true);
        }
    }
}
