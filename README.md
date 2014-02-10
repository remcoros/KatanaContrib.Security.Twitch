KatanaContrib.Security.Twitch
===========================

This is a fork from https://github.com/KatanaContrib/KatanaContrib.Security.Github, with some adjustments to support Twitch.tv OAuth implementation.

- instead of GET, use url form encoded POST to get token
- update claims to match Twitch user object
- update default scope to match scope used by Twitch (user_read)
- twitch requires the redirect_uri to match exactly, so make sure to set 'redirect Uri' to '<absolute url>/signin-twitch' in your twitch control panel

**KatanaContrib.Security.Twitch** provides a [Katana](http://katanaproject.codeplex.com/) middleware that supports the LinkedIn authentication flow. 

The KatanaContrib.Security.Twitch was designed and implemented similar to [Microsoft.Owin.Security.Facebook](https://www.nuget.org/packages/Microsoft.Owin.Security.Facebook) and [Microsoft.Owin.Security.Twitter](https://www.nuget.org/packages/Microsoft.Owin.Security.Twitter) this allows you to use it the same way as the security middlewares provided by Microsoft.  
How to use in MVC5 project: 
--------
A couple of actions will need to be done under the App_Start folder in the Startup.Auth.cs file :
 
* Add namespace  `using KatanaContrib.Security.Twitch;`
* In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..
    
        app.UseTwitchAuthentication("YOUR_APP_CLIENT_ID", "YOUR_APP_CLIENT_SECRET");
    
        //... custom code ...
}
```
* If you need to pass more params application scope for instance pass a `TwitchAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..
    
        app.UseTwitchAuthentication(new TwitchAuthenticationOptions()
        {
                ClientId = "YOUR_APP_CLIENT_ID",
                ClientSecret = "YOUR_APP_SECRET_KEY",
                Scope = new List<string>() { "channel_read" },
        });

    
        //... custom code ...
}
```

> **Note:** By default the `user_read` scope is always beeing added. This allows to fetch the authenticating users email.