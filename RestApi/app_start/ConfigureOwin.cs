using Microsoft.Owin.Cors;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Http;

namespace RestApi
{
    public partial class ConfigureOwin
    {
        public void Configure(IAppBuilder appBuilder)
        {         
            var config = new HttpConfiguration();
            ConfigureRoutes(config);
            ConfigureOAuth(appBuilder);
            //appBuilder.UseCors(new CorsOptions { PolicyProvider = new CorsPolicyProvider() });
            appBuilder.UseCors(CorsOptions.AllowAll);
            appBuilder.UseWebApi(config);
        }
    }
}
