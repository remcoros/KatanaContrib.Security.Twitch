namespace KatanaContrib.Security.Twitch
{
    using System;
    using System.Globalization;
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    using Newtonsoft.Json.Linq;

    public class TwitchAuthenticatedContext : BaseContext
    {
        public TwitchAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            this.User = user;
            this.AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                this.ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            this.Id = TryGetValue(user, "_id");
            this.DisplayName = TryGetValue(user, "display_name");
            this.Email = TryGetValue(user, "email");
            this.UserName = TryGetValue(user, "name");
            JToken links;
            if (user.TryGetValue("_links", out links))
            {
                var self = links["self"];
                if (self != null)
                    this.Url = self.ToString();
            }
        }

        public JObject User { get; private set; }

        public string DisplayName { get; private set; }
        public string Id { get; private set; }
        public string Email { get; private set; }
        public string Url { get; private set; }
        public string UserName { get; private set; }


        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }
        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
