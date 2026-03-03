# OpenID Telegram Connect (OIDC) Provider for Laravel Socialite

![Laravel Support: v9, v10, v11, v12](https://img.shields.io/badge/Laravel%20Support-v9%2C%20v10%2C%20v11%2C%20v12-blue) ![PHP Support: 8.1, 8.2, 8.3](https://img.shields.io/badge/PHP%20Support-8.1%2C%208.2%2C%208.3-blue)

## Installation & Basic Usage

```bash
composer require e4se/laravel-telegram-oidc
```

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

### Add configuration to `config/services.php`

```php
'telegram-oidc' => [
    'client_id' => env('TELEGRAM_OIDC_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_OIDC_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_OIDC_REDIRECT_URI')
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

### Customizing the scopes

You may extend the default scopes (`openid profile`) by adding a `scopes` option to your OIDC service configuration and separate multiple scopes with a space:

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

---

Based on the work of [Kovah](https://github.com/Kovah)
