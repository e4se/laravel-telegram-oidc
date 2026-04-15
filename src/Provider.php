<?php

namespace SocialiteProviders\TelegramOIDC;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Cache;
use JsonException;
use SocialiteProviders\Manager\Contracts\ConfigInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

/**
 * Generic OpenID Connect provider for Laravel Socialite
 *
 * @see https://docs.whmcs.com/OpenID_Connect_Developer_Guide
 */
class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'TELEGRAM-OIDC';

    public const BASE_URL = 'https://oauth.telegram.org';

    public $configurations = null;

    /**
     * {@inheritdoc}
     */
    protected $scopes = [
        // required; to indicate that the application intends to use OIDC to verify the user's identity
        // Returns the sub claim, which uniquely identifies the user.
        // Also presents in an ID Token : iss, aud, exp, iat, c_hash.
        'openid',

        // Returns claims that represent basic profile information
        // name, id, preferred_username, picture
        'profile',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * Indicates if the nonce should be utilized.
     *
     * @var bool
     */
    protected bool $usesNonce = true;

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return [
            'scopes',
            'proxy',
            'connect_timeout',
            'timeout',
            'use_pkce',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function setConfig(ConfigInterface $config)
    {
        parent::setConfig($config);

        $this->configureHttpClient();

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function redirect(): RedirectResponse
    {
        $state = null;

        if ($this->usesState()) {
            $this->request->session()->put('state', $state = $this->getState());
        }

        if ($this->usesNonce()) {
            $this->request->session()->put('nonce', $this->getNonce());
        }

        if ($this->usesPKCE()) {
            $this->request->session()->put('code_verifier', $this->getCodeVerifier());
        }

        return new RedirectResponse($this->getAuthUrl($state));
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(): array
    {
        if ($this->getConfig('scopes')) {
            return array_merge($this->scopes, explode(' ', $this->getConfig('scopes')));
        }

        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getOpenIdConfig()['token_endpoint'];
    }

    /**
     * Get the user_info URL for the provider.
     *
     * @return string
     * @throws GuzzleException
     */
    protected function getUserInfoUrl()
    {
        $userInfoUrl = $this->getOpenIdConfig()['userinfo_endpoint'] ?? null;

        if (! is_string($userInfoUrl) || $userInfoUrl === '') {
            throw new ConfigurationFetchingException(
                'Telegram OIDC does not currently expose a separate userinfo endpoint. ' .
                'Use the ID token returned by the authorization code flow.'
            );
        }

        return $userInfoUrl;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(
            $this->getOpenIdConfig()['authorization_endpoint'],
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function buildAuthUrlFromBase($url, $state): string
    {
        return $url . '?' . http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null): array
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        if ($this->usesNonce()) {
            // Implicit flow nonce
            // https://auth0.com/docs/authorization/flows/mitigate-replay-attacks-when-using-the-implicit-flow
            $fields['nonce'] = $this->getCurrentNonce();
        }

        if ($this->usesPKCE()) {
            $fields['code_challenge'] = $this->getCodeChallenge();
            $fields['code_challenge_method'] = $this->getCodeChallengeMethod();
        }

        return array_merge($fields, $this->parameters);
    }

    /**
     * Telegram recommends PKCE for the authorization code flow.
     */
    protected function usesPKCE()
    {
        return (bool) $this->getProviderConfigValue('use_pkce', true);
    }

    /**
     * Determine if the provider is operating with nonce.
     *
     * @return bool
     */
    protected function usesNonce(): bool
    {
        return $this->usesNonce;
    }

    /**
     * Get the string used for nonce.
     *
     * @return string
     */
    protected function getNonce(): string
    {
        return Str::random(40);
    }

    /**
     * Apply provider-level HTTP client options while preserving explicit guzzle overrides.
     */
    protected function configureHttpClient(): void
    {
        $configuredOptions = array_filter([
            'proxy' => $this->getProviderConfigValue('proxy'),
            'connect_timeout' => $this->getProviderConfigValue('connect_timeout'),
            'timeout' => $this->getProviderConfigValue('timeout'),
        ], static fn ($value) => $value !== null && $value !== '');

        if ($configuredOptions === []) {
            return;
        }

        $this->guzzle = array_replace($configuredOptions, $this->guzzle);
        $this->httpClient = null;
    }

    /**
     * Read a top-level provider config value without treating explicit false as "missing".
     */
    protected function getProviderConfigValue(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->config) ? $this->config[$key] : $default;
    }

    /**
     * Get the current string used for nonce.
     *
     * @return string
     */
    protected function getCurrentNonce()
    {
        $nonce = null;

        if ($this->request->session()->has('nonce')) {
            $nonce = $this->request->session()->get('nonce');
        }

        return $nonce;
    }

    /**
     * @return array OpenID data for OIDC
     * @throws GuzzleException
     */
    protected function getOpenIdConfig()
    {
        if ($this->configurations === null) {
            try {
                $configUrl = self::BASE_URL. '/.well-known/openid-configuration';

                $response = $this->getHttpClient()->get($configUrl);

                $this->configurations = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            } catch (Exception $e) {
                throw new ConfigurationFetchingException('Unable to get the OIDC configuration from ' . $configUrl . ': ' . $e->getMessage());
            }
        }

        return $this->configurations;
    }

    /**
     * Get JWKS (JSON Web Key Set) from the OIDC provider
     *
     * @return array
     * @throws GuzzleException
     */
    protected function getJwks()
    {
        $cacheKey = 'oidc_jwks_' . md5(self::BASE_URL);
        
        return Cache::remember($cacheKey, 3600, function () {
            $config = $this->getOpenIdConfig();
            
            if (!isset($config['jwks_uri'])) {
                throw new JwtVerificationException('JWKS URI not found in OIDC configuration');
            }
            
            try {
                $response = $this->getHttpClient()->get($config['jwks_uri']);
                return json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            } catch (Exception $e) {
                throw new JwtVerificationException('Unable to fetch JWKS: ' . $e->getMessage());
            }
        });
    }

    /**
     * Receive data from auth/callback route
     * code, id_token, scope, state, session_state
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException("Callback: invalid state.", 401);
        }

        $code = $this->request->input('code');

        if (! is_string($code) || $code === '') {
            throw new InvalidCodeException('Callback: missing authorization code.', 400);
        }

        $tokenResponse = $this->getAccessTokenResponse($code);

        if (! isset($tokenResponse['id_token']) || ! is_string($tokenResponse['id_token'])) {
            throw new InvalidTokenException('Token response: missing id_token.', 401);
        }

        $payload = $this->decodeJWT($tokenResponse['id_token']);

        $this->user = $this->mapUserToObject((array)$payload);

        return $this->user->setToken($tokenResponse['access_token'])
            ->setRefreshToken($tokenResponse['refresh_token'] ?? null)
            ->setExpiresIn($tokenResponse['expires_in']);
    }

    protected function decodeJWT($jwt)
    {
        return $this->verifyAndDecodeJWT($jwt);
    }

    /**
     * Verify JWT signature and decode the token
     *
     * @param string $jwt
     * @return object
     * @throws JwtVerificationException
     */
    protected function verifyAndDecodeJWT($jwt)
    {
        try {
            $jwks = $this->getJwks();
            $keySet = JWK::parseKeySet($jwks);
            $decoded = JWT::decode($jwt, $keySet);

            // Convert to object format for compatibility
            $payload = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), false, 512, JSON_THROW_ON_ERROR);

            $this->assertValidIdTokenClaims($payload);

            if ($this->isInvalidNonce($payload->nonce ?? null)) {
                throw new InvalidNonceException('JWT: Contains an invalid nonce.', 401);
            }

            if ($this->usesNonce()) {
                $this->request->session()->forget('nonce');
            }

            return $payload;
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new JwtVerificationException('JWT: Token has expired.', 401);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new JwtVerificationException('JWT: Invalid signature.', 401);
        } catch (\Firebase\JWT\InvalidTokenException $e) {
            throw new JwtVerificationException('JWT: Invalid token format.', 401);
        } catch (JsonException $e) {
            throw new JwtVerificationException('JWT: Failed to decode payload.', 401);
        } catch (Exception $e) {
            throw new JwtVerificationException('JWT: Verification failed - ' . $e->getMessage(), 401);
        }
    }

    /**
     * JWT::decode() already validates time-based claims, including configured leeway.
     * This helper only checks claims Firebase JWT does not enforce for us.
     */
    protected function assertValidIdTokenClaims(object $payload): void
    {
        if (($payload->iss ?? null) !== self::BASE_URL) {
            throw new JwtVerificationException('JWT: Invalid issuer.', 401);
        }

        $audience = $payload->aud ?? null;
        $expectedAudience = (string) $this->clientId;
        $tokenAudiences = is_array($audience)
            ? array_map('strval', $audience)
            : (is_scalar($audience) ? [(string) $audience] : []);

        if (! in_array($expectedAudience, $tokenAudiences, true)) {
            throw new JwtVerificationException('JWT: Invalid audience.', 401);
        }
    }

    /**
     * Determine if the current token has a mismatching "nonce".
     * nonce must be validated to prevent replay attacks
     *
     * @return bool
     */
    protected function isInvalidNonce($nonce)
    {
        if (!$this->usesNonce()) {
            return false;
        }

        return !(strlen($nonce) > 0 && $nonce === $this->getCurrentNonce());
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())
            ->setRaw($user)
            ->map(
            [
                'id' => $user['id'] ?? $user['sub'],
                'name' => $user['name'] ?? null,
                'nickname' => $user['preferred_username'] ?? null,
                'avatar' => $user['picture'] ?? null,
            ]
        );
    }

    /**
     * {@inheritdoc}
     * @throws JsonException|GuzzleException
     */
    public function getAccessTokenResponse($code)
    {
        $tokenFields = array_merge(
            $this->getTokenFields($code),
            [
                'grant_type' => 'authorization_code',
            ]
        );

        unset($tokenFields['client_secret']);

        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::AUTH => [$this->clientId, $this->clientSecret],
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => $tokenFields,
        ]);

        return json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }


    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            $this->getUserInfoUrl() . '?' . http_build_query([
                'access_token' => $token,
            ]),
            [
                RequestOptions::HEADERS => [
                    'Accept' => 'application/json',
                ],
            ]
        );

        return json_decode((string)$response->getBody(), true);
    }

}
