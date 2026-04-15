<?php

declare(strict_types=1);

namespace SocialiteProviders\TelegramOIDC\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;
use SocialiteProviders\Manager\Config;
use SocialiteProviders\TelegramOIDC\JwtVerificationException;
use SocialiteProviders\TelegramOIDC\Provider;

final class ProviderTest extends TestCase
{
    public function test_it_merges_top_level_proxy_config_into_guzzle_options(): void
    {
        $provider = $this->makeProvider([
            'proxy' => 'http://127.0.0.1:8080',
            'connect_timeout' => 10.0,
            'timeout' => 20.0,
        ]);

        $guzzle = $this->readProviderProperty($provider, 'guzzle');

        self::assertSame('http://127.0.0.1:8080', $guzzle['proxy']);
        self::assertSame(10.0, $guzzle['connect_timeout']);
        self::assertSame(20.0, $guzzle['timeout']);
    }

    public function test_explicit_guzzle_options_override_top_level_proxy_defaults(): void
    {
        $provider = $this->makeProvider([
            'proxy' => 'http://127.0.0.1:8080',
            'connect_timeout' => 10.0,
            'timeout' => 20.0,
            'guzzle' => [
                'proxy' => 'socks5h://127.0.0.1:9050',
                'timeout' => 30.0,
                'verify' => false,
            ],
        ]);

        $guzzle = $this->readProviderProperty($provider, 'guzzle');

        self::assertSame('socks5h://127.0.0.1:9050', $guzzle['proxy']);
        self::assertSame(10.0, $guzzle['connect_timeout']);
        self::assertSame(30.0, $guzzle['timeout']);
        self::assertFalse($guzzle['verify']);
    }

    public function test_it_enables_pkce_by_default(): void
    {
        $provider = $this->makeProvider();

        $method = new ReflectionMethod($provider, 'usesPKCE');
        $method->setAccessible(true);

        self::assertTrue($method->invoke($provider));
    }

    public function test_it_allows_disabling_pkce_for_compatibility(): void
    {
        $provider = $this->makeProvider([
            'use_pkce' => false,
        ]);

        $method = new ReflectionMethod($provider, 'usesPKCE');
        $method->setAccessible(true);

        self::assertFalse($method->invoke($provider));
    }

    public function test_it_exchanges_the_authorization_code_using_basic_auth(): void
    {
        $provider = $this->makeProvider();
        $request = $this->readProviderProperty($provider, 'request');
        $request->session()->put('code_verifier', 'telegram-pkce-verifier');
        $this->writeProviderProperty($provider, 'configurations', [
            'token_endpoint' => 'https://oauth.telegram.org/token',
        ]);

        $history = [];
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'telegram-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'id_token' => 'telegram-id-token',
            ], JSON_THROW_ON_ERROR)),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $handlerStack->push(Middleware::history($history));

        $provider->setHttpClient(new Client([
            'handler' => $handlerStack,
        ]));

        $provider->getAccessTokenResponse('telegram-auth-code');

        self::assertCount(1, $history);

        $tokenRequest = $history[0]['request'];
        parse_str((string) $tokenRequest->getBody(), $formParams);

        self::assertSame(
            'Basic ' . base64_encode('telegram-client-id:telegram-client-secret'),
            $tokenRequest->getHeaderLine('Authorization')
        );
        self::assertSame('authorization_code', $formParams['grant_type']);
        self::assertSame('telegram-client-id', $formParams['client_id']);
        self::assertSame('telegram-auth-code', $formParams['code']);
        self::assertSame('https://example.com/auth/telegram/callback', $formParams['redirect_uri']);
        self::assertSame('telegram-pkce-verifier', $formParams['code_verifier']);
        self::assertArrayNotHasKey('client_secret', $formParams);
    }

    public function test_it_rejects_invalid_issuer_claims(): void
    {
        $provider = $this->makeProvider();

        $method = new ReflectionMethod($provider, 'assertValidIdTokenClaims');
        $method->setAccessible(true);

        $this->expectException(JwtVerificationException::class);
        $this->expectExceptionMessage('JWT: Invalid issuer.');

        $method->invoke($provider, (object) [
            'iss' => 'https://example.com',
            'aud' => 'telegram-client-id',
            'exp' => time() + 3600,
        ]);
    }

    public function test_it_rejects_invalid_audience_claims(): void
    {
        $provider = $this->makeProvider();

        $method = new ReflectionMethod($provider, 'assertValidIdTokenClaims');
        $method->setAccessible(true);

        $this->expectException(JwtVerificationException::class);
        $this->expectExceptionMessage('JWT: Invalid audience.');

        $method->invoke($provider, (object) [
            'iss' => 'https://oauth.telegram.org',
            'aud' => 'another-client-id',
            'exp' => time() + 3600,
        ]);
    }

    public function test_it_does_not_second_guess_firebase_jwt_expiry_handling(): void
    {
        $provider = $this->makeProvider();

        $method = new ReflectionMethod($provider, 'assertValidIdTokenClaims');
        $method->setAccessible(true);

        $method->invoke($provider, (object) [
            'iss' => 'https://oauth.telegram.org',
            'aud' => 'telegram-client-id',
            'exp' => time() - 30,
        ]);

        $this->addToAssertionCount(1);
    }

    private function makeProvider(array $config = []): Provider
    {
        $provider = new Provider(
            $this->makeRequestWithSession(),
            'telegram-client-id',
            'telegram-client-secret',
            'https://example.com/auth/telegram/callback',
            $config['guzzle'] ?? [],
        );

        $provider->setConfig(new Config(
            'telegram-client-id',
            'telegram-client-secret',
            'https://example.com/auth/telegram/callback',
            $config,
        ));

        return $provider;
    }

    private function makeRequestWithSession(): Request
    {
        $request = Request::create('/auth/telegram/callback', 'GET');
        $request->setLaravelSession(new Store('telegram-oidc-test', new ArraySessionHandler(120)));

        return $request;
    }

    private function readProviderProperty(Provider $provider, string $property): mixed
    {
        $reflection = new ReflectionProperty($provider, $property);
        $reflection->setAccessible(true);

        return $reflection->getValue($provider);
    }

    private function writeProviderProperty(Provider $provider, string $property, mixed $value): void
    {
        $reflection = new ReflectionProperty($provider, $property);
        $reflection->setAccessible(true);
        $reflection->setValue($provider, $value);
    }
}
