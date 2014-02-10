namespace KatanaContrib.Security.Twitch
{
    using System;
    using System.Globalization;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using Owin;

    public class TwitchAuthenticationMiddleware : AuthenticationMiddleware<TwitchAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public TwitchAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
             TwitchAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(this.Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", "AppId"));
            }
            if (string.IsNullOrWhiteSpace(this.Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", "AppSecret"));
            }
            if (!this.Options.Scope.Contains(Constants.DefaultScope))
            {
                this.Options.Scope.Add(Constants.DefaultScope);
            }

            this._logger = app.CreateLogger<TwitchAuthenticationMiddleware>();

            if (this.Options.Provider == null)
            {
                this.Options.Provider = new TwitchAuthenticationProvider();
            }
            if (this.Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(TwitchAuthenticationMiddleware).FullName,
                    this.Options.AuthenticationType, "v1");
                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (String.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
            {
                this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            this._httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options));
            this._httpClient.Timeout = this.Options.BackchannelTimeout;
            this._httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<TwitchAuthenticationOptions> CreateHandler()
        {
            return new TwitchAuthenticationHandler(this._httpClient, this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(TwitchAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
