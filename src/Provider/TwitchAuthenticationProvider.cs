namespace KatanaContrib.Security.Twitch
{
    using System;
    using System.Threading.Tasks;

    public class TwitchAuthenticationProvider : ITwitchAuthenticationProvider
    {
        public TwitchAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
        }
        public Func<TwitchAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<TwitchReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(TwitchAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(TwitchReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}
