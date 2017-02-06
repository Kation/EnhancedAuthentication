using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class EnhancedAuthenticationCertificateProvider : IEnhancedAuthenticationCertificateProvider
    {
        private static object _Lock;
        private static readonly string _RevokePrefix = "revoked_";

        public EnhancedAuthenticationCertificateProvider(string root)
        {
            _Root = new DirectoryInfo(root + Path.DirectorySeparatorChar + "certs");
            _CertId = _Root.FullName + Path.DirectorySeparatorChar + "certId";
            if (!_Root.Exists)
            {
                _Root.Create();
                File.WriteAllText(_CertId, "1", Encoding.ASCII);
            }
            else
            {
                var files = _Root.GetFiles(_RevokePrefix + "*", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                    if (file.LastWriteTime <= DateTime.Now)
                        file.Delete();
            }
        }

        private string _CertId;
        private DirectoryInfo _Root;

        public int KeySize { get { return 2048; } }

        private TimeSpan _Period = TimeSpan.FromDays(365);
        public TimeSpan Period { get { return _Period; } }

        public Task<bool> CheckIsRevoked(int certId)
        {
            return Task.FromResult(File.Exists(_Root.FullName + Path.DirectorySeparatorChar + _RevokePrefix + certId));
        }

        public Task<int[]> GetRevokedListAsync(DateTime? startDate)
        {
            var files = _Root.GetFiles(_RevokePrefix + "*", SearchOption.TopDirectoryOnly);
            if (startDate.HasValue)
                files = files.Where(t => t.CreationTime >= startDate).ToArray();
            return Task.FromResult(files.Select(t => int.Parse(t.Name.Substring(8))).ToArray());
        }

        public Task<int> NewIdAsync()
        {
            Monitor.Enter(_Lock);
            try
            {
                var lastId = int.Parse(File.ReadAllText(_CertId, Encoding.ASCII));
                lastId++;
                File.WriteAllText(_CertId, lastId.ToString(), Encoding.ASCII);
                return Task.FromResult(lastId);
            }
            finally
            {
                Monitor.Exit(_Lock);
            }
        }

        public Task RevokeAsync(int certId, DateTime expiredDate)
        {
            if (expiredDate <= DateTime.Now)
                return Task.CompletedTask;
            string filename = _Root.FullName + Path.DirectorySeparatorChar + _RevokePrefix + certId;
            FileInfo file = new FileInfo(filename);
            file.Create().Dispose();
            file.LastWriteTime = expiredDate;
            return Task.CompletedTask;
        }

        public Task NewCertificateAsync(EnhancedAuthenticationCertificate cert)
        {
            return Task.CompletedTask;
        }
    }
}
