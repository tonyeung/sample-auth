using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Threading;
using System.Configuration;
using Microsoft.Owin.Security.DataProtection;
using System.Security.Cryptography;
using System.IO;
using System.Security;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataHandler.Encoder;

namespace RestApi
{
    public partial class ConfigureOwin
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();
            OAuthBearerOptions.AccessTokenFormat = new SecureTokenFormatter("2EDD1F0FAE8BD3780D2F7559775CB3BD95701CF87B4FAA4A22D2FE019D09F9E30D85DD8E5F0261DC468BC41999AD199AB271EAE25E937D08CDAFADBB72B3D639");


            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(1),
                AccessTokenFormat = new SecureTokenFormatter("2EDD1F0FAE8BD3780D2F7559775CB3BD95701CF87B4FAA4A22D2FE019D09F9E30D85DD8E5F0261DC468BC41999AD199AB271EAE25E937D08CDAFADBB72B3D639"),
                Provider = new SimpleAuthorizationServerProvider()//,
                //RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);
        }
    }

    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            var props = new AuthenticationProperties(new Dictionary<string, string>());
            var ticket = new AuthenticationTicket(identity, props);

            context.Validated(identity);
        }

        //public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        //{
        //    foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
        //    {
        //        context.AdditionalResponseParameters.Add(property.Key, property.Value);
        //    }

        //    return Task.FromResult<object>(null);
        //}

        //public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        //{
        //    var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
        //    var currentClient = context.ClientId;

        //    if (originalClient != currentClient)
        //    {
        //        context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
        //        return Task.FromResult<object>(null);
        //    }

        //    // Change auth ticket for refresh token requests
        //    var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

        //    var newClaim = newIdentity.Claims.Where(c => c.Type == "newClaim").FirstOrDefault();
        //    if (newClaim != null)
        //    {
        //        newIdentity.RemoveClaim(newClaim);
        //    }
        //    newIdentity.AddClaim(new Claim("newClaim", "newValue"));

        //    var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
        //    context.Validated(newTicket);

        //    return Task.FromResult<object>(null);
        //}
    }

    //public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    //{
    //    public Task CreateAsync(AuthenticationTokenCreateContext context)
    //    {
    //        var clientid = context.Ticket.Properties.Dictionary["as:client_id"];

    //        if (string.IsNullOrEmpty(clientid))
    //        {
    //            return Task.FromResult<object>(null);
    //        }

    //        var refreshTokenId = Guid.NewGuid().ToString("n");

    //        var refreshTokenLifeTime = context.OwinContext.Get<string>("as:clientRefreshTokenLifeTime");
    //        var dealercode = string.Empty;
    //        if (context.Ticket.Properties.Dictionary.ContainsKey("dealercode"))
    //        {
    //            dealercode = context.Ticket.Properties.Dictionary["dealercode"];
    //        }
    //        else throw new Exception("dealercode not found");

    //        var username = context.Ticket.Identity.Name;
            
    //        var token = new AMS.AccessControl.API.DTOs.RefreshToken()
    //        {
    //            TokenId = refreshTokenId, //"4b6539959fdb47e1bce834335ee05d47", //refreshTokenId,
    //            ClientId = clientid,
    //            Subject = username + ":" + dealercode,
    //            IssuedUtc = DateTime.UtcNow,
    //            ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
    //        };

    //        context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
    //        context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

    //        token.ProtectedTicket = context.SerializeTicket();

    //        AccessControlAPI accessControlAPI = new AccessControlAPI(null);
    //        var result = accessControlAPI.SaveToken(token).Result;

    //        if (result)
    //        {
    //            context.SetToken(refreshTokenId);
    //        }
    //        return Task.FromResult<object>(result);
    //    }

    //    public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
    //    {

    //        var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
    //        context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

    //        AccessControlAPI accessControlAPI = new AccessControlAPI(null);
    //        var refreshToken = accessControlAPI.GetToken(context.Token).Result;

    //        if (refreshToken != null)
    //        {
    //            //Get protectedTicket from refreshToken class
    //            context.DeserializeTicket(refreshToken.ProtectedTicket);
    //            var result = accessControlAPI.DeleteToken(refreshToken.Id).Result;
    //        }
    //        return Task.FromResult<object>(null);
    //    }

    //    public void Create(AuthenticationTokenCreateContext context)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public void Receive(AuthenticationTokenReceiveContext context)
    //    {
    //        throw new NotImplementedException();
    //    }
    //}
    public class SecureTokenFormatter : ISecureDataFormat<AuthenticationTicket>
    {
        #region Fields

        private TicketSerializer serializer;
        private IDataProtector protector;
        private ITextEncoder encoder;

        #endregion Fields

        #region Constructors

        public SecureTokenFormatter(string key)
        {
            this.serializer = new TicketSerializer();
            this.protector = new AesDataProtectorProvider(key);
            this.encoder = TextEncodings.Base64Url;
        }

        #endregion Constructors

        #region ISecureDataFormat<AuthenticationTicket> Members

        public string Protect(AuthenticationTicket ticket)
        {
            var ticketData = this.serializer.Serialize(ticket);
            var protectedData = this.protector.Protect(ticketData);
            var protectedString = this.encoder.Encode(protectedData);
            return protectedString;
        }

        public AuthenticationTicket Unprotect(string text)
        {
            var protectedData = this.encoder.Decode(text);
            var ticketData = this.protector.Unprotect(protectedData);
            var ticket = this.serializer.Deserialize(ticketData);
            return ticket;
        }

        #endregion ISecureDataFormat<AuthenticationTicket> Members
    }

    internal class AesDataProtectorProvider : IDataProtector
    {
        #region Fields

        private byte[] key;

        #endregion Fields

        #region Constructors

        public AesDataProtectorProvider(string key)
        {
            using (var sha1 = new SHA256Managed())
            {
                this.key = sha1.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }

        #endregion Constructors

        #region IDataProtector Methods

        public byte[] Protect(byte[] data)
        {
            byte[] dataHash;
            using (var sha = new SHA256Managed())
            {
                dataHash = sha.ComputeHash(data);
            }

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = this.key;
                aesAlg.GenerateIV();

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(aesAlg.IV, 0, 16);

                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var bwEncrypt = new BinaryWriter(csEncrypt))
                    {
                        bwEncrypt.Write(dataHash);
                        bwEncrypt.Write(data.Length);
                        bwEncrypt.Write(data);
                    }
                    var protectedData = msEncrypt.ToArray();
                    return protectedData;
                }
            }
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = this.key;

                using (var msDecrypt = new MemoryStream(protectedData))
                {
                    byte[] iv = new byte[16];
                    msDecrypt.Read(iv, 0, 16);

                    aesAlg.IV = iv;

                    using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (var brDecrypt = new BinaryReader(csDecrypt))
                    {
                        var signature = brDecrypt.ReadBytes(32);
                        var len = brDecrypt.ReadInt32();
                        var data = brDecrypt.ReadBytes(len);

                        byte[] dataHash;
                        using (var sha = new SHA256Managed())
                        {
                            dataHash = sha.ComputeHash(data);
                        }

                        if (!dataHash.SequenceEqual(signature))
                            throw new SecurityException("Signature does not match the computed hash");

                        return data;
                    }
                }
            }
        }

        #endregion IDataProtector Methods
    }
}
