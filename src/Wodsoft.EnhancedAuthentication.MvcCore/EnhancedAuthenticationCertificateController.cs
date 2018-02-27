using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.MvcCore
{
    /// <summary>
    /// 增强认证证书服务。
    /// </summary>
    public abstract class EnhancedAuthenticationCertificateController : ControllerBase
    {
        /// <summary>
        /// 请求证书。
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public virtual async Task<IActionResult> RequestCertificate()
        {
            if (!await CheckIsAdminAsync())
                return Unauthorized();
            var appInfo = GetAppInformationFromRequest();
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            var cert = await service.CreateCertificateAsync(appInfo);
            return File(cert.ExportCertificate(true), "application/octet-stream");
        }

        /// <summary>
        /// 从请求里获取应用信息。
        /// </summary>
        /// <returns></returns>
        protected virtual AppInformation GetAppInformationFromRequest()
        {
            return new AppInformation { AppId = Request.Form["appId"] };
        }

        /// <summary>
        /// 检查是否有管理权限。
        /// </summary>
        /// <returns></returns>
        protected abstract Task<bool> CheckIsAdminAsync();

        /// <summary>
        /// 申请证书。
        /// </summary>
        /// <param name="callback">申请成功后通知地址。</param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> ApplyCertificate([FromQuery]string callback)
        {
            var appInfo = GetAppInformationFromRequest();
            await ApplyCertificateCore(appInfo, callback);
            return Ok();
        }

        /// <summary>
        /// 申请证书内部实现。
        /// </summary>
        /// <param name="appInfo">应用信息。</param>
        /// <param name="callbakUrl">申请成功后通知地址。</param>
        /// <returns></returns>
        protected abstract Task ApplyCertificateCore(AppInformation appInfo, string callbakUrl);

        /// <summary>
        /// 撤销的证书列表。
        /// </summary>
        /// <param name="startDate">查询起始时间。</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> RevokedCertificate([FromQuery]DateTime? startDate)
        {
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            var list = await service.GetRevokedCertificateListAsync(startDate);
            return Content(string.Join(",", list));
        }

        /// <summary>
        /// 续签证书。
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> RenewCertificate()
        {
            EnhancedAuthenticationCertificate certificate;
            try
            {
                certificate = HttpContext.VerifyServiceRequest("root.certificate");
            }
            catch
            {
                return Unauthorized();
            }
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            certificate = await service.RenewCertificateAsync(certificate);
            return File(certificate.ExportCertificate(true), "application/octet-stream");
        }

        /// <summary>
        /// 请求根证书。
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public virtual Task<IActionResult> RootCertificate()
        {
            var service = HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationService>();
            return Task.FromResult<IActionResult>(File(service.Certificate.ExportCertificate(false), "application/octet-stream", "root.pem"));
        }

        /// <summary>
        /// 请求用户令牌。
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public virtual async Task<IActionResult> Authorize([FromQuery]string cert, [FromQuery]byte requestLevel, [FromQuery]string returnUrl, [FromQuery]string rnd)
        {
            byte[] rndData;
            try
            {
                rndData = Convert.FromBase64String(rnd);
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
                return Redirect(userProvider.GetSignInUrl(Url.Action("Authorize", new { cert = cert, requestLevel = requestLevel, returnUrl = returnUrl, rnd = rnd })));
            var levelStatus = user.CurrentLevel >= requestLevel ? UserLevelStatus.Authorized : (user.MaximumLevel >= requestLevel ? UserLevelStatus.Unconfirmed : UserLevelStatus.Unauthorized);
            if (levelStatus == UserLevelStatus.Unauthorized)
                return Redirect(returnUrl + "?status=unauthorized");
            else if (levelStatus == UserLevelStatus.Unconfirmed)
                return Redirect(userProvider.GetConfirmUrl(Url.Action("Authorize", new { cert = cert, requestLevel = requestLevel, returnUrl = returnUrl, rnd = rnd })));
            string signature;
            var token = service.GetUserToken(certificate, user, requestLevel, rndData, out signature);
            return Redirect(returnUrl + "?status=success&token=" + Uri.EscapeDataString(token) + "&signature=" + Uri.EscapeDataString(signature));
        }

    }
}
