using Microsoft.Owin.Cors;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Cors;


namespace RestApi
{
    public class CorsPolicyProvider : ICorsPolicyProvider
    {
        private CorsPolicy _policy;

        public CorsPolicyProvider()
        {
            // Create a CORS policy.
            _policy = new CorsPolicy
            {
                AllowAnyMethod = true,
                AllowAnyHeader = true
            };

            _policy.Origins.Add("https://localhost:8000");
        }

        public Task<CorsPolicy> GetCorsPolicyAsync(Microsoft.Owin.IOwinRequest request)
        {
            return Task.FromResult(_policy);
        }
    }
}
