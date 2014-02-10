namespace KatanaContrib.Security.Twitch
{
    using System;

    using Owin;

    public static class TwitchAuthenticationExtensions
    {
        public static IAppBuilder UseTwitchAuthentication(this IAppBuilder app, TwitchAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(TwitchAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseTwitchAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseTwitchAuthentication(
                app,
                new TwitchAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
        }
    }
}
