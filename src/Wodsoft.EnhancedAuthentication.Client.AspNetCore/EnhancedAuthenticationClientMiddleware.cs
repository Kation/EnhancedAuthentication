﻿using System;
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
    public class EnhancedAuthenticationClientMiddleware
    {
        private readonly RequestDelegate _Next;
        private readonly PathString _SignInPath, _AuthorizePath;

        public EnhancedAuthenticationClientMiddleware(RequestDelegate next, PathString path)
        {
            _Next = next;
            _SignInPath = path.Add("/SignIn");
            _AuthorizePath = path.Add("/Authorize");
        }

        public async Task Invoke(HttpContext httpContext)
        {
            var client = httpContext.RequestServices.GetRequiredService<EnhancedAuthenticationClient>();
            if (httpContext.Request.Path.StartsWithSegments(httpContext.Request.PathBase.Add(_SignInPath)))
            {
                if (!httpContext.Request.Query.ContainsKey("requestLevel"))
                {
                    httpContext.Response.StatusCode = 400;
                    return;
                }
                string returnUrl = httpContext.Request.Scheme + "://" + httpContext.Request.Host + httpContext.Request.PathBase + _AuthorizePath;
                if (httpContext.Request.Query.ContainsKey("returnUrl"))
                    returnUrl += "?returnUrl=" + Convert.ToBase64String(Encoding.ASCII.GetBytes(Uri.EscapeUriString(httpContext.Request.Query["returnUrl"])));
                Uri jump = client.GetAuthorizeUrl(httpContext.Request.Query["requestLevel"], returnUrl);
                httpContext.Response.Redirect(jump.AbsoluteUri, false);
                return;
            }
            else if (httpContext.Request.Path.StartsWithSegments(httpContext.Request.PathBase.Add(_AuthorizePath)))
            {
                if (!httpContext.Request.Query.ContainsKey("status"))
                {
                    httpContext.Response.StatusCode = 400;
                    return;
                }
                string status = httpContext.Request.Query["status"];
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
                        tokenData = client.AppCertificate.Cryptography.Decrypt(Convert.FromBase64String(httpContext.Request.Query["token"]), RSAEncryptionPadding.Pkcs1);
                        token = JsonConvert.DeserializeObject<UserToken>(Encoding.ASCII.GetString(tokenData));
                        signature = Convert.FromBase64String(httpContext.Request.Query["signature"]);
                    }
                    catch
                    {
                        httpContext.Response.StatusCode = 400;
                        return;
                    }
                    if (!client.RootCertificate.Cryptography.VerifyData(tokenData, signature, client.RootCertificate.HashMode))
                    {
                        httpContext.Response.StatusCode = 401;
                        return;
                    }
                    var handler = httpContext.RequestServices.GetRequiredService<IEnhancedAuthenticationClientHandler>();
                    var result = new EnhancedAuthenticationClientAuthorizeResult(httpContext, token);
                    await handler.Authorize(result);
                    if (result.IsHandled)
                        return;
                }
                else if (status == "unauthorized")
                {
                    var handler = httpContext.RequestServices.GetRequiredService<IEnhancedAuthenticationClientHandler>();
                    var result = new EnhancedAuthenticationClientAuthorizeResult(httpContext, null);
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