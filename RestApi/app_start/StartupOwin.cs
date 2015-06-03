using Microsoft.Owin.Hosting;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using Topshelf;

namespace RestApi
{
    public class StartUpOwin
    {

        protected IDisposable OwinWebApp
        {
            get;
            set;
        }

        public bool Start(HostControl hostControl)
        {
            if (OwinWebApp == null)
            {
                var baseUrl = ConfigurationManager.ConnectionStrings["BaseUrl"].ToString();
                var options = new StartOptions(baseUrl);

                OwinWebApp = WebApp.Start
                (
                    options,
                    appBuilder =>
                    {
                        new ConfigureOwin().Configure(appBuilder);
                    }
                );

            }

            return true;
        }

        public bool Stop(HostControl hostControl)
        {
            if (OwinWebApp != null)
            {
                OwinWebApp.Dispose();
                OwinWebApp = null;
            }

            return true;
        }
    }
}
