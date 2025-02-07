---
sidebar_position: 99
---

# FAQ

## How can i get more log output from the plugin

The default log level of the plugin is set to `WARN`. You can change this by specifying the `LogLevel` option in the [configuration](./middleware-configuration.md).

## I get stuck in a redirect loop after signing in

Make sure you're using HTTPS. The session cookie is configured as *Secure* by default which means it will only be stored, when using HTTPS.
If you open the Browser's development console you might see a warning icon (at least in Google Chrome) telling you that you're not on a secure context.
In the traefik logs you might see the message `named cookie is not present` which is also a sign that the session cookie hasn't been stored.
If you really can't use HTTPS you can set `SessionCookie.Secure` to `false`, but please don't do this in production.

## I just see *Unauthorized* after signing in

This normally means, that your user isn't authorized to sign in. Please check the traefik logs to get more information.
You may see something like `Unauthorized. Unable to find claim roles in token claims.`. It will also output all the claims contained in the token.
Please adjust your `Authorization`-config accordingly.
