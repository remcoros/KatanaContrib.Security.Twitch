namespace KatanaContrib.Security.Twitch
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    public class TwitchAuthenticationOptions : AuthenticationOptions
    {
        public TwitchAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            this.Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-twitch");
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.Scope = new List<string>() { Constants.DefaultScope };
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }


        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public string Caption
        {
            get { return this.Description.Caption; }
            set { this.Description.Caption = value; }
        }

        public PathString CallbackPath { get; set; }
        public string SignInAsAuthenticationType { get; set; }
        public ITwitchAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IList<string> Scope { get; set; }
    }
}
