using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Wodsoft.EnhancedAuthentication.Sample.ServiceHost
{
    public class RoutePreMiddleware
    {
        private readonly RequestDelegate _Next;
        private readonly IRouter _Router;

        public RoutePreMiddleware(RequestDelegate next, IRouter router)
        {
            _Next = next;
            _Router = router;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            var context = new RouteContext(httpContext);
            context.RouteData.Routers.Add(_Router);

            await _Router.RouteAsync(context);

            if (context.Handler != null)
            {
                httpContext.Features[typeof(IRoutingFeature)] = new RoutingFeature()
                {
                    RouteData = context.RouteData,
                };
            }

            await _Next(httpContext);
        }
    }
}
