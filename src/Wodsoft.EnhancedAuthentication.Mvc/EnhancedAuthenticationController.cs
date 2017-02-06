using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Mvc
{
    //[RequireHttps]
    public abstract class EnhancedAuthenticationController : ControllerBase
    {
        /// <summary>
        /// 请求证书。
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> RequestCertificate([FromForm]string username, [FromForm]string password)
        {
            if (!await CheckIsAdmin(username, password))
                return Unauthorized();
            var appInfo = GetAppInformation();
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            var cert = await service.CreateCertificateAsync(appInfo);
            return File(cert.ExportCertificate(true), "application/octet-stream");
        }

        protected virtual AppInformation GetAppInformation()
        {
            return new AppInformation { AppId = Request.Form["appId"] };
        }

        protected abstract Task<bool> CheckIsAdmin(string username, string password);

        /// <summary>
        /// 申请证书。
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> ApplyCertificate([FromQuery]string callback)
        {
            var appInfo = GetAppInformation();
            await ApplyCertificateCore(appInfo, callback);
            return Ok();
        }

        protected abstract Task ApplyCertificateCore(AppInformation appInfo, string callbakUrl);

        /// <summary>
        /// 撤销的证书列表。
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> RevokedCertificate([FromQuery]DateTime? startDate)
        {
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            var list = await service.RevokedCertificateList(startDate);
            return Content(string.Join(",", list));
        }

        /// <summary>
        /// 续签证书。
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> RenewCertificate([FromForm]string cert, [FromQuery]int expiredDate, [FromQuery]string signature)
        {
            var eDate = new DateTime(expiredDate);
            if (cert == null || eDate < DateTime.Now || signature == null)
                return BadRequest();
            EnhancedAuthenticationCertificate certificate;
            try
            {
                var certData = Convert.FromBase64String(cert);
                certificate = new EnhancedAuthenticationCertificate(certData);
            }
            catch
            {
                return Unauthorized();
            }
            byte[] signData;
            try
            {
                signData = Convert.FromBase64String(signature);
            }
            catch
            {
                return BadRequest();
            }
            if (!certificate.Cryptography.VerifyData(BitConverter.GetBytes(expiredDate), signData, certificate.HashMode))
                return Unauthorized();
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            certificate = await service.RenewCertificate(certificate);
            return File(certificate.ExportCertificate(true), "application/octet-stream");
        }

        [HttpGet]
        public virtual Task<IActionResult> RootCertificate()
        {
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            return Task.FromResult<IActionResult>(File(service.Certificate.ExportCertificate(false), "application/octet-stream"));
        }

        /// <summary>
        /// 请求用户令牌。
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public virtual async Task<IActionResult> Authorize([FromQuery]string cert, [FromQuery]string requestLevel, [FromQuery]string returnUrl)
        {
            string tReturnUrl;
            try
            {
                tReturnUrl = Encoding.ASCII.GetString(Convert.FromBase64String(returnUrl));
            }
            catch
            {
                return BadRequest();
            }
            EnhancedAuthenticationCertificate certificate;
            try
            {
                var certData = Convert.FromBase64String(cert);
                certificate = new EnhancedAuthenticationCertificate(certData);
            }
            catch
            {
                return Unauthorized();
            }
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            if (!service.Certificate.VerifyCertificate(certificate))
                return Unauthorized();
            var userProvider = HttpContext.RequestServices.GetRequiredService<IEnhancedAuthenticationUserProvider>();
            var user = await userProvider.GetUserAsync();
            if (user == null)
                return Redirect(userProvider.GetSignInUrl(Url.Action("Authorize", new { cert = cert, requestLevel = requestLevel, returnUrl = returnUrl })));
            var levelStatus = userProvider.CheckLevel(user, requestLevel);
            if (levelStatus == UserLevelStatus.Unauthorized)
                return Redirect(returnUrl + "?status=unauthorized");
            else if (levelStatus == UserLevelStatus.Unconfirmed)
                return Redirect(userProvider.GetConfirmUrl(Url.Action("Authorize", new { cert = cert, requestLevel = requestLevel, returnUrl = returnUrl })));
            string signature;
            var token = service.GetUserToken(certificate, user, requestLevel, out signature);
            return Redirect(returnUrl + "?status=success&token=" + token + "&signature=" + signature);
        }
    }
}
