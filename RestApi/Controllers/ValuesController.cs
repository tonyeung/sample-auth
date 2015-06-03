using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Configuration;
using System.Threading.Tasks;

namespace RestApi.Controllers
{
    public class ValuesController : ApiController
    {
        public ValuesController()
        {
        }

        [Authorize]
        [Route("authenticated")]
        public HttpResponseMessage GetAuthenticated()
        {
            return Request.CreateResponse(HttpStatusCode.OK, "Authenticated");
        }

        [Route("unauthenticated")]
        public HttpResponseMessage GetUnAuthenticated()
        {
            return Request.CreateResponse(HttpStatusCode.OK, "Unauthenticated");
        }
    }
}
