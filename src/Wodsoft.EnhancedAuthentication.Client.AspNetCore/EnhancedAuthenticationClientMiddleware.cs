using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text;
using Newtonsoft.Json;
using System.Security.Cryptography;

namespace Wodsoft.EnhancedAuthentication.Client.AspNetCore
{
    /// <summary>
    /// 增强认证客户端中间件。
    /// </summary>
    public class EnhancedAuthenticationClientMiddleware
    {
        private readonly RequestDelegate _Next;
        private readonly PathString _SignInPath, _AuthorizePath;
        private readonly EnhancedAuthenticationProvider _Provider;
        private readonly string _AuthorizeUrl;

        /// <summary>
        /// 实例化中间件。
        /// </summary>
        /// <param name="next">下一请求委托。</param>
        /// <param name="provider">增强认证提供器。</param>
        /// <param name="options">配置选项。</param>
        public EnhancedAuthenticationClientMiddleware(RequestDelegate next, EnhancedAuthenticationProvider provider, EnhancedAuthenticationClientMiddlewareOptions options)
        {
            _Next = next;
            _Provider = provider;
            _SignInPath = options.BasePath.Add("/SignIn");
            _AuthorizePath = options.BasePath.Add("/Authorize");
            _AuthorizeUrl = options.AuthorizeUrl;
        }

        /// <summary>
        /// 执行中间件。
        /// </summary>
        /// <param name="httpContext">Http上下文。</param>
        /// <returns></returns>
        public async Task Invoke(HttpContext httpContext)
        {
            var provider = httpContext.RequestServices.GetRequiredService<EnhancedAuthenticationProvider>();
            if (httpContext.Request.Path.StartsWithSegments(httpContext.Request.PathBase.Add(_SignInPath)))
            {
                byte requestLevel = 0;
                if (httpContext.Request.Query.ContainsKey("requestLevel"))
                {
                    if (!byte.TryParse(httpContext.Request.Query["requestLevel"], out requestLevel))
                    {
                        httpContext.Response.StatusCode = 400;
                        return;
                    }
                }
                string returnUrl = httpContext.Request.Scheme + "://" + httpContext.Request.Host + httpContext.Request.PathBase + _AuthorizePath;
                if (httpContext.Request.Query.ContainsKey("returnUrl"))
                    httpContext.Session.Set("eAuth_return", Encoding.ASCII.GetBytes(httpContext.Request.Query["returnUrl"]));
                Random rnd = new Random();
                var rndValue = BitConverter.GetBytes(rnd.NextDouble());
                httpContext.Session.Set("eAuth_rnd", rndValue);
                string cert = Convert.ToBase64String(_Provider.AppCertificate.ExportCertificate(false));
                Uri jump = new Uri(_AuthorizeUrl + "?cert=" + Uri.EscapeDataString(cert) + "&requestLevel=" + requestLevel + "&returnUrl=" + Uri.EscapeDataString(returnUrl) + "&rnd=" + Uri.EscapeDataString(Convert.ToBase64String(rndValue)));
                httpContext.Response.Redirect(jump.AbsoluteUri, false);
                return;
            }
            else if (httpContext.Request.Path.StartsWithSegments(httpContext.Request.PathBase.Add(_AuthorizePath)))
            {
                byte[] rndValue;
                if (!httpContext.Session.TryGetValue("eAuth_rnd", out rndValue))
                {
                    httpContext.Response.StatusCode = 401;
                    return;
                }
                if (!httpContext.Request.Query.ContainsKey("status"))
                {
                    httpContext.Response.StatusCode = 400;
                    return;
                }
                string status = httpContext.Request.Query["status"];
                string returnUrl = null;
                byte[] returnUrlData;
                if (httpContext.Session.TryGetValue("eAuth_return", out returnUrlData))
                    returnUrl = Encoding.ASCII.GetString(returnUrlData);
                if (status == "success")
                {
                    if (!httpContext.Request.Query.ContainsKey("token") || !httpContext.Request.Query.ContainsKey("signature"))
                    {
                        httpContext.Response.StatusCode = 400;
                        return;
                    }
                    UserToken token;
                    byte[] tokenData;
                    byte[] signature;
                    try
                    {
                        tokenData = provider.AppCertificate.Cryptography.Decrypt(Convert.FromBase64String(httpContext.Request.Query["token"]));
                        token = JsonConvert.DeserializeObject<UserToken>(Encoding.ASCII.GetString(tokenData));
                        signature = Convert.FromBase64String(httpContext.Request.Query["signature"]);
                    }
                    catch
                    {
                        httpContext.Response.StatusCode = 400;
                        return;
                    }
                    if (!provider.RootCertificate.Cryptography.VerifyData(tokenData.Concat(rndValue).ToArray(), signature, provider.RootCertificate.HashMode))
                    {
                        httpContext.Response.StatusCode = 401;
                        return;
                    }
                    httpContext.Session.Remove("eAuth_rnd");
                    var handler = httpContext.RequestServices.GetRequiredService<IEnhancedAuthenticationClientHandler>();
                    var result = new EnhancedAuthenticationClientAuthorizeResult(httpContext, token, returnUrl);
                    await handler.Authorize(result);
                    if (result.IsHandled)
                        return;
                }
                else if (status == "unauthorized")
                {
                    var handler = httpContext.RequestServices.GetRequiredService<IEnhancedAuthenticationClientHandler>();
                    var result = new EnhancedAuthenticationClientAuthorizeResult(httpContext, null, returnUrl);
                    await handler.Authorize(result);
                    if (result.IsHandled)
                        return;
                }
                else
                {
                    httpContext.Response.StatusCode = 400;
                    return;
                }
            }
            await _Next(httpContext);
        }
    }
}
