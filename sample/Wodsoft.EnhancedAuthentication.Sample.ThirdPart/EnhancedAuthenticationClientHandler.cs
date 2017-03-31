using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Wodsoft.ComBoost.Data.Entity;
using Wodsoft.ComBoost.Security;
using Wodsoft.EnhancedAuthentication.Client.AspNetCore;
using Wodsoft.EnhancedAuthentication.Sample.ThirdPart.Models;

namespace Wodsoft.EnhancedAuthentication.Sample.ThirdPart
{
    public class EnhancedAuthenticationClientHandler : IEnhancedAuthenticationClientHandler
    {
        public async Task Authorize(EnhancedAuthenticationClientAuthorizeResult result)
        {
            if (result.IsSuccess)
            {
                var authenticationProvider = result.HttpContext.RequestServices.GetRequiredService<IAuthenticationProvider>();
                var databaseContext = result.HttpContext.RequestServices.GetRequiredService<IDatabaseContext>();
                var memberContext = databaseContext.GetContext<Member>();
                Guid id = Guid.Parse(result.UserToken.UserId);
                var member = await memberContext.GetAsync(id);
                if (member == null)
                {
                    var client = result.HttpContext.RequestServices.GetRequiredService<EnhancedAuthenticationClient>();
                    FormUrlEncodedContent requestContent = new FormUrlEncodedContent(new Dictionary<string, string>() { { "id", result.UserToken.UserId } });
                    var responseContent = await client.RequestService("GetUserInfo", requestContent);
                    var json = JsonConvert.DeserializeObject<JToken>(await responseContent.ReadAsStringAsync());
                    member = memberContext.Create();
                    member.Index = id;
                    member.Username = json.Value<string>("username");
                    memberContext.Add(member);
                    await databaseContext.SaveAsync();
                }
                member.CurrentLevel = (AccessLevel)result.UserToken.CurrentLevel;
                member.MaximumLevel = (AccessLevel)result.UserToken.MaximumLevel;
                await authenticationProvider.SignInAsync(member);
                result.IsHandled = false;
            }
        }
    }
}
