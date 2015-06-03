using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Topshelf;

namespace RestApi
{
    class Program
    {
        static void Main(string[] args)
        {
            HostFactory.Run(x =>
            {
                x.Service<StartUpOwin>
                (
                    s =>
                    {
                        s.ConstructUsing(() => new StartUpOwin());
                        s.WhenStarted((service, hostControl) => service.Start(hostControl));
                        s.WhenStopped((service, hostControl) => service.Stop(hostControl));
                    }
                );

                x.RunAsLocalSystem();
                x.SetDescription("RestApi");
                x.SetDisplayName("RestApi");
                x.SetServiceName("RestApi");
            });
        }
    }
}
