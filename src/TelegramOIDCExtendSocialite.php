<?php

namespace SocialiteProviders\TelegramOIDC;

use SocialiteProviders\Manager\SocialiteWasCalled;

class TelegramOIDCExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('telegram-oidc', Provider::class);
    }
}
