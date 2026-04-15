# OpenID Telegram Connect (OIDC) Provider for Laravel Socialite

![Laravel Support: v9, v10, v11, v12](https://img.shields.io/badge/Laravel%20Support-v9%2C%20v10%2C%20v11%2C%20v12-blue) ![PHP Support: 8.1, 8.2, 8.3](https://img.shields.io/badge/PHP%20Support-8.1%2C%208.2%2C%208.3-blue)

## Installation & Basic Usage

```bash
composer require e4se/laravel-telegram-oidc
```

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

This provider implements Telegram's current OpenID Connect login flow documented at
[core.telegram.org/bots/telegram-login](https://core.telegram.org/bots/telegram-login).

### Telegram setup

Before configuring Laravel, make sure your bot is prepared in Telegram:

- Open `@BotFather` and navigate to `Bot Settings > Web Login`
- Register every allowed website origin and callback URL you plan to use
- Copy the `Client ID` and `Client Secret` shown by BotFather

Telegram only accepts login requests and redirects for pre-registered URLs.

### Add configuration to `config/services.php`

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
],
```

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

#### Laravel 11+

In Laravel 11, the default `EventServiceProvider` provider was removed. Instead, add the listener using the `listen` method on the `Event` facade, in your `AppServiceProvider` `boot` method.

```php
Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
    $event->extendSocialite('telegram-oidc', \SocialiteProviders\TelegramOIDC\Provider::class);
});
```

#### Laravel 10 or below

Add the event to your listen[] array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \SocialiteProviders\TelegramOIDC\TelegramOIDCExtendSocialite::class.'@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade
installed):

```php
return Socialite::driver('telegram-oidc')->redirect();
```

By default the provider uses PKCE (`S256`) and validates the returned `id_token` against Telegram's JWKS,
including `iss`, `aud`, and `exp`, as required by the official documentation.

### Returned User fields

- `id`
- `name`
- `nickname`
- `avatar`

More fields are available under the `user` subkey:

```php
$user = Socialite::driver('telegram-oidc')->user();

$phone_number = $user->user['phone_number'];
```

Telegram returns user claims directly in the `id_token`. Telegram does not currently expose a separate
`userinfo` endpoint, so this provider reads the authenticated user from the validated ID token instead.

### Customizing the scopes

You may extend the default scopes (`openid profile`) by adding a `scopes` option to your OIDC service
configuration and separate multiple scopes with a space. Telegram currently documents `phone` and
`telegram:bot_access` as additional available scopes:

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'scopes' => 'phone',
    // or
    'scopes' => env('TELEGRAM_OIDC_SCOPES'),
],
```

### PKCE

PKCE is enabled by default to match Telegram's recommended authorization code flow. If you need to disable it
for compatibility testing, you can do so explicitly:

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'use_pkce' => false,
],
```

### Proxy and HTTP timeouts

You may route Telegram OIDC requests through a proxy directly from the provider config:

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'proxy' => env('TELEGRAM_OIDC_PROXY', env('TELEGRAM_PROXY')),
    'connect_timeout' => env('TELEGRAM_OIDC_CONNECT_TIMEOUT'),
    'timeout' => env('TELEGRAM_OIDC_TIMEOUT'),
],
```

For advanced transport customization you can still pass raw Guzzle options via `guzzle`. Explicit `guzzle` options take precedence over the top-level `proxy`, `connect_timeout`, and `timeout` keys:

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI'),
    'proxy' => env('TELEGRAM_OIDC_PROXY'),
    'guzzle' => array_filter([
        'proxy' => env('TELEGRAM_OIDC_GUZZLE_PROXY'),
        'verify' => env('TELEGRAM_OIDC_VERIFY_TLS', true),
    ], static fn ($value) => $value !== null && $value !== ''),
],
```

---

Based on the work of [Kovah](https://github.com/Kovah)
