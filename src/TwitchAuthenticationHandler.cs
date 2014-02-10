namespace KatanaContrib.Security.Twitch
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json.Linq;

    internal class TwitchAuthenticationHandler : AuthenticationHandler<TwitchAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string AuthorizeEndpoint = "https://api.twitch.tv/kraken/oauth2/authorize";
        private const string TokenEndpoint = "https://api.twitch.tv/kraken/oauth2/token";
        private const string ApiEndpoint = "https://api.twitch.tv/kraken/user?oauth_token=";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public TwitchAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = this.Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = this.Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!this.ValidateCorrelationId(properties, this._logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = this.Request.Scheme + "://" + this.Request.Host;
                string redirectUri = requestPrefix + this.Request.PathBase + this.Options.CallbackPath;


                var tokenRequest = new Dictionary<string, string>();
                tokenRequest["grant_type"] = "authorization_code";
                tokenRequest["code"] = code;
                tokenRequest["redirect_uri"] = redirectUri;
                tokenRequest["client_id"] = this.Options.ClientId;
                tokenRequest["client_secret"] = this.Options.ClientSecret;

                var postContent = new FormUrlEncodedContent(tokenRequest);
                HttpResponseMessage tokenResponse = await this._httpClient.PostAsync(TokenEndpoint, postContent, this.Request.CallCancelled);

                tokenResponse.EnsureSuccessStatusCode();

                string text = await tokenResponse.Content.ReadAsStringAsync();

                //Parsing the string to a JSON Object
                JObject jsonText = JObject.Parse(text);

                //Extracting the access token from the JSON Object
                JToken accessToken;
                jsonText.TryGetValue("access_token", out accessToken);

                //Set the expiration time 60 days (5183999 seconds)
                string expires = "5183999";

                //As Twitch required to include a User Agent in all requests, set User Agent in the request header
                this._httpClient.DefaultRequestHeaders.Add("user-agent", "Owin Twitch Integration");

                HttpResponseMessage API_Response = await this._httpClient.GetAsync(
                    ApiEndpoint + Uri.EscapeDataString(accessToken.ToString()), this.Request.CallCancelled);

                API_Response.EnsureSuccessStatusCode();
                text = await API_Response.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new TwitchAuthenticatedContext(this.Context, user, accessToken.ToString(), expires);

                context.Identity = new ClaimsIdentity(
                    this.Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                //Add context properties to the Claims Identity
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DisplayName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.DisplayName, XmlSchemaString, this.Options.AuthenticationType));
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.DisplayName, XmlSchemaString, this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Url))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Webpage, context.Url, XmlSchemaString, this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim("urn:twitch:login", context.UserName, XmlSchemaString, this.Options.AuthenticationType));
                }

                context.Properties = properties;

                await this.Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                this._logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    this.Request.Scheme +
                    Uri.SchemeDelimiter +
                    this.Request.Host +
                    this.Request.PathBase;

                string currentUri =
                    baseUri +
                    this.Request.Path +
                    this.Request.QueryString;

                string redirectUri =
                    baseUri +
                    this.Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                this.GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", this.Options.Scope);

                string state = this.Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    AuthorizeEndpoint +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(this.Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                this.Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await this.InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (this.Options.CallbackPath.HasValue && this.Options.CallbackPath == this.Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await this.AuthenticateAsync();
                if (ticket == null)
                {
                    this._logger.WriteWarning("Invalid return state, unable to redirect.");
                    this.Response.StatusCode = 500;
                    return true;
                }

                var context = new TwitchReturnEndpointContext(this.Context, ticket);
                context.SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await this.Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    this.Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    this.Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}
