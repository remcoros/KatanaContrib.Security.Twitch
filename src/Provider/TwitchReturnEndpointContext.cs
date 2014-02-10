namespace KatanaContrib.Security.Twitch
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class TwitchReturnEndpointContext : ReturnEndpointContext
    {
        public TwitchReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
