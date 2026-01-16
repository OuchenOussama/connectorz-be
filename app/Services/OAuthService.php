<?php

namespace App\Services;

use App\Models\OAuthConnection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OAuthService
{

    private array $connectors = [
        'gmail' => [
            'auth_url' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url' => 'https://oauth2.googleapis.com/token',
            'client_id' => 'GOOGLE_CLIENT_ID',
            'client_secret' => 'GOOGLE_CLIENT_SECRET',
        ],
        'linkedin' => [
            'auth_url' => 'https://www.linkedin.com/oauth/v2/authorization',
            'token_url' => 'https://www.linkedin.com/oauth/v2/accessToken',
            'client_id' => 'LINKEDIN_CLIENT_ID',
            'client_secret' => 'LINKEDIN_CLIENT_SECRET',
        ],
        'stripe' => [
            'auth_url' => 'https://connect.stripe.com/oauth/authorize',
            'token_url' => 'https://connect.stripe.com/oauth/token',
            'client_id' => 'STRIPE_CLIENT_ID',
            'client_secret' => 'STRIPE_CLIENT_SECRET',
        ],
        'shopify' => [
            'auth_url' => '{shop}/admin/oauth/authorize',
            'token_url' => '{shop}/admin/oauth/access_token',
            'client_id' => 'SHOPIFY_CLIENT_ID',
            'client_secret' => 'SHOPIFY_CLIENT_SECRET',
        ],
        'facebook' => [
            'auth_url' => 'https://www.facebook.com/v18.0/dialog/oauth',
            'token_url' => 'https://graph.facebook.com/v18.0/oauth/access_token',
            'client_id' => 'FACEBOOK_CLIENT_ID',
            'client_secret' => 'FACEBOOK_CLIENT_SECRET',
        ],
        'instagram' => [
            'auth_url' => 'https://www.instagram.com/oauth/authorize',
            'token_url' => 'https://api.instagram.com/oauth/access_token',
            'client_id' => 'INSTAGRAM_CLIENT_ID',
            'client_secret' => 'INSTAGRAM_CLIENT_SECRET',
        ],
        'tiktok' => [
            'auth_url' => 'https://www.tiktok.com/v2/auth/authorize',
            'token_url' => 'https://open.tiktokapis.com/v2/oauth/token',
            'client_id' => 'TIKTOK_CLIENT_ID',
            'client_secret' => 'TIKTOK_CLIENT_SECRET',
        ],
        'notion' => [
            'auth_url' => 'https://api.notion.com/v1/oauth/authorize',
            'token_url' => 'https://api.notion.com/v1/oauth/token',
            'client_id' => 'NOTION_CLIENT_ID',
            'client_secret' => 'NOTION_CLIENT_SECRET',
        ],
        'paypal' => [
            'auth_url' => 'https://www.sandbox.paypal.com/connect',
            'token_url' => 'https://api-m.sandbox.paypal.com/v1/oauth2/token',
            'client_id' => 'PAYPAL_CLIENT_ID',
            'client_secret' => 'PAYPAL_CLIENT_SECRET',
        ],
        'slack' => [
            'auth_url' => 'https://slack.com/oauth/v2/authorize',
            'token_url' => 'https://slack.com/api/oauth.v2.access',
            'client_id' => 'SLACK_CLIENT_ID',
            'client_secret' => 'SLACK_CLIENT_SECRET',
        ],
    ];

    public function generateAuthUrl(string $connectorId, string $userId, string $scopes, ?string $redirectUri = null, ?string $shop = null): array
    {
        // Get connector config or use Google as default for Google services
        $connector = $this->connectors[$connectorId] ?? $this->getDefaultConnector($connectorId);
        
        // Handle Shopify dynamic URLs
        if ($connectorId === 'shopify') {
            if (!$shop) {
                throw new \InvalidArgumentException('Shop parameter is required for Shopify');
            }
            $connector['auth_url'] = "https://{$shop}/admin/oauth/authorize";
            $connector['token_url'] = "https://{$shop}/admin/oauth/access_token";
            $state = base64_encode(json_encode([
                'user_id' => $userId,
                'connector_id' => $connectorId,
                'csrf_token' => Str::random(32),
                'shop' => $shop,
            ]));
        } else {
            $state = base64_encode(json_encode([
                'user_id' => $userId,
                'connector_id' => $connectorId,
                'csrf_token' => Str::random(32),
            ]));
        }

        $params = [
            'client_id' => env($connector['client_id']),
            'redirect_uri' => $redirectUri ?: config('app.url') . '/api/oauth/callback',
            'scope' => $scopes,
            'response_type' => 'code',
            'state' => $state,
            'access_type' => 'offline',
            'prompt' => 'consent',
        ];

        // Slack requires HTTPS - use localtunnel URL - TODO : Change at Production
        if ($connectorId === 'slack') {
            $params['redirect_uri'] = $redirectUri ?: 'https://violet-parents-double.loca.lt/api/oauth/callback';
            unset($params['access_type'], $params['prompt']);
        }

        // Shopify doesn't use access_type and prompt
        if ($connectorId === 'shopify') {
            unset($params['access_type'], $params['prompt']);
        }
        
        // PayPal requires flowEntry parameter and different param names
        if ($connectorId === 'paypal') {
            $params = [
                'client_id' => env($connector['client_id']),
                'response_type' => 'code',
                'scope' => $scopes,
                'redirect_uri' => $redirectUri ?: config('app.url') . '/api/oauth/callback',
                'state' => $state,
                'flowEntry' => 'static',
            ];
        }
        
        // TikTok requires PKCE
        if ($connectorId === 'tiktok') {
            $codeVerifier = Str::random(64);
            $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
            $params['code_challenge'] = $codeChallenge;
            $params['code_challenge_method'] = 'S256';
            unset($params['access_type'], $params['prompt']);
            session(['tiktok_code_verifier_' . $userId => $codeVerifier]);
        }

        $authUrl = $connector['auth_url'] . '?' . http_build_query($params);

        return [
            'authUrl' => $authUrl,
            'state' => $state,
            'connectorId' => $connectorId,
        ];
    }

    private function getDefaultConnector(string $connectorId): array
    {
        // Map connectors to OAuth providers
        $googleServices = ['youtube', 'calendar', 'drive', 'gmail', 'google-calendar', 'google-drive', 'google-youtube', 'google-business'];
        $facebookServices = ['facebook', 'whatsapp'];
        
        if (in_array($connectorId, $googleServices)) {
            return $this->connectors['gmail'];
        }
        
        if (in_array($connectorId, $facebookServices)) {
            return $this->connectors['facebook'];
        }

        // For any other connector, return a generic OAuth2 config
        return [
            'auth_url' => 'https://oauth.provider.com/authorize',
            'token_url' => 'https://oauth.provider.com/token',
            'client_id' => 'GOOGLE_CLIENT_ID', // Default to Google
            'client_secret' => 'GOOGLE_CLIENT_SECRET',
        ];
    }

    public function exchangeCodeForTokens(string $connectorId, string $code, string $redirectUri, ?string $userId = null, ?string $shop = null): array
    {
        $connector = $this->connectors[$connectorId] ?? $this->getDefaultConnector($connectorId);
        
        // Handle Shopify dynamic URLs
        if ($connectorId === 'shopify') {
            if (!$shop) {
                throw new \InvalidArgumentException('Shop parameter is required for Shopify');
            }
            $connector['token_url'] = "https://{$shop}/admin/oauth/access_token";
        }
        
        $params = [
            'client_id' => env($connector['client_id']),
            'client_secret' => env($connector['client_secret']),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirectUri,
        ];

        // Slack requires the same redirect_uri used in authorization
        if ($connectorId === 'slack') {
            $params['redirect_uri'] = 'https://violet-parents-double.loca.lt/api/oauth/callback';
        }

        // TikTok requires PKCE code_verifier
        if ($connectorId === 'tiktok' && $userId) {
            $params['code_verifier'] = session('tiktok_code_verifier_' . $userId);
            session()->forget('tiktok_code_verifier_' . $userId);
        }

        // Notion requires Basic Auth
        if ($connectorId === 'notion') {
            $auth = base64_encode(env($connector['client_id']) . ':' . env($connector['client_secret']));
            unset($params['client_id'], $params['client_secret']);
            $response = Http::withoutVerifying()
                ->withHeaders(['Authorization' => 'Basic ' . $auth])
                ->asJson()
                ->post($connector['token_url'], $params);
        } elseif ($connectorId === 'paypal') {
            $auth = base64_encode(env($connector['client_id']) . ':' . env($connector['client_secret']));
            $response = Http::withoutVerifying()
                ->withHeaders(['Authorization' => 'Basic ' . $auth])
                ->asForm()
                ->post($connector['token_url'], [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                ]);
        } else {
            $response = Http::withoutVerifying()->asForm()->post($connector['token_url'], $params);
        }

        if (!$response->successful()) {
            throw new \Exception("Failed to exchange code for tokens: " . $response->body());
        }

        $data = $response->json();
        \Log::info('Token exchange response', ['connector' => $connectorId, 'data' => $data]);
        
        // Slack returns tokens in different structure
        if ($connectorId === 'slack') {
            if (isset($data['authed_user']['access_token'])) {
                return [
                    'access_token' => $data['authed_user']['access_token'],
                    'token_type' => 'Bearer',
                    'scope' => $data['authed_user']['scope'] ?? '',
                    'team' => $data['team'] ?? [],
                    'authed_user' => $data['authed_user'],
                ];
            } elseif (isset($data['access_token'])) {
                return $data;
            } else {
                throw new \Exception("Slack token response missing access_token: " . json_encode($data));
            }
        }

        return $data;
    }

    public function storeConnection(string $userId, string $connectorId, array $tokenData, array $scopes, ?string $shop = null): OAuthConnection
    {
        // Shopify - fetch shop metadata using access token
        if ($connectorId === 'shopify' && $shop) {
            $metadata = $this->getConnectorMetadata($connectorId, $tokenData['access_token'], $shop);
            $accountId = $metadata['domain'] ?? $metadata['myshopify_domain'] ?? $shop;
        } else {
            $metadata = $this->getConnectorMetadata($connectorId, $tokenData['access_token']);
            $accountId = $this->extractAccountIdentifier($connectorId, $metadata);
        }

        return OAuthConnection::updateOrCreate(
            [
                'user_id' => $userId,
                'connector_id' => $connectorId,
                'account_identifier' => $accountId
            ],
            [
                'access_token' => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'] ?? null,
                'token_type' => $tokenData['token_type'] ?? 'Bearer',
                'expires_at' => isset($tokenData['expires_in']) 
                    ? now()->addSeconds($tokenData['expires_in']) 
                    : null,
                'scopes' => $scopes,
                'status' => 'active',
                'connector_metadata' => $metadata,
                'granted_at' => now(),
            ]
        );
    }

    private function extractAccountIdentifier(string $connectorId, array $metadata): ?string
    {
        // Google services use email
        $googleServices = ['youtube', 'calendar', 'drive', 'gmail', 'google-calendar', 'google-drive', 'google-youtube', 'google-business'];
        
        if (in_array($connectorId, $googleServices)) {
            return $metadata['email'] ?? $metadata['id'] ?? null;
        }

        // Facebook services use id
        $facebookServices = ['facebook', 'whatsapp'];
        if (in_array($connectorId, $facebookServices)) {
            return $metadata['id'] ?? null;
        }

        return match($connectorId) {
            'linkedin' => $metadata['sub'] ?? $metadata['id'] ?? null,
            'instagram' => $metadata['user_id'] ?? $metadata['id'] ?? null,
            'tiktok' => $metadata['open_id'] ?? $metadata['union_id'] ?? null,
            'stripe' => $metadata['stripe_user_id'] ?? null,
            'shopify' => $metadata['domain'] ?? $metadata['myshopify_domain'] ?? null,
            'notion' => $metadata['workspace_id'] ?? $metadata['id'] ?? null,
            'paypal' => $metadata['user_id'] ?? $metadata['payer_id'] ?? null,
            'slack' => $metadata['user_id'] ?? $metadata['team_id'] ?? null,
            default => $metadata['id'] ?? $metadata['email'] ?? $metadata['sub'] ?? null,
        };
    }

    public function refreshAccessToken(string $connectorId, string $refreshToken): array
    {
        if (!isset($this->connectors[$connectorId])) {
            throw new \InvalidArgumentException("Unsupported connector: {$connectorId}");
        }

        $connector = $this->connectors[$connectorId];
        
        $response = Http::withoutVerifying()->asForm()->post($connector['token_url'], [
            'client_id' => env($connector['client_id']),
            'client_secret' => env($connector['client_secret']),
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
        ]);

        if (!$response->successful()) {
            throw new \Exception("Failed to refresh token: " . $response->body());
        }

        return $response->json();
    }

    private function getConnectorMetadata(string $connectorId, string $accessToken, ?string $shop = null): array
    {
        try {
            // Google services use same userinfo endpoint
            $googleServices = ['youtube', 'calendar', 'drive', 'gmail', 'google-calendar', 'google-drive', 'google-youtube', 'google-business'];
            
            if (in_array($connectorId, $googleServices)) {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->get('https://www.googleapis.com/oauth2/v2/userinfo');
                return $response->successful() ? $response->json() : [];
            }

            // Facebook services use Graph API
            $facebookServices = ['facebook', 'whatsapp'];
            if (in_array($connectorId, $facebookServices)) {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->get('https://graph.facebook.com/me?fields=id,name,email,picture');
                return $response->successful() ? $response->json() : [];
            }

            // Instagram uses its own API
            if ($connectorId === 'instagram') {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->get('https://graph.instagram.com/me?fields=id,username,account_type');
                return $response->successful() ? $response->json() : [];
            }

            // TikTok uses its own API
            if ($connectorId === 'tiktok') {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->post('https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name');
                return $response->successful() ? $response->json()['data']['user'] ?? [] : [];
            }

            // Notion uses its own API
            if ($connectorId === 'notion') {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->withHeaders(['Notion-Version' => '2022-06-28'])
                    ->get('https://api.notion.com/v1/users/me');
                if ($response->successful()) {
                    $data = $response->json();
                    // Get workspace details
                    $workspaceResponse = Http::withoutVerifying()->withToken($accessToken)
                        ->withHeaders(['Notion-Version' => '2022-06-28'])
                        ->post('https://api.notion.com/v1/search', ['page_size' => 1]);
                    
                    $metadata = [
                        'workspace_id' => $data['bot']['workspace_id'] ?? null,
                        'workspace_name' => $data['bot']['workspace_name'] ?? null,
                        'workspace_icon' => $data['bot']['workspace_icon'] ?? null,
                        'user_id' => $data['bot']['owner']['user']['id'] ?? null,
                        'user_name' => $data['bot']['owner']['user']['name'] ?? null,
                        'user_email' => $data['bot']['owner']['user']['person']['email'] ?? null,
                        'user_avatar' => $data['bot']['owner']['user']['avatar_url'] ?? null,
                    ];
                    return $metadata;
                }
                return [];
            }

            // PayPal uses its own API
            if ($connectorId === 'paypal') {
                $response = Http::withoutVerifying()->withToken($accessToken)
                    ->get('https://api.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1');
                return $response->successful() ? $response->json() : [];
            }

            // Slack uses its own API
            if ($connectorId === 'slack') {
                $authResponse = Http::withoutVerifying()->withToken($accessToken)
                    ->get('https://slack.com/api/auth.test');
                $authData = $authResponse->json();
                
                if ($authData['ok'] && isset($authData['user_id'])) {
                    $userResponse = Http::withoutVerifying()->withToken($accessToken)
                        ->get('https://slack.com/api/users.info?user=' . $authData['user_id']);
                    $userData = $userResponse->json();
                    
                    if ($userData['ok']) {
                        return array_merge($authData, [
                            'user_profile' => $userData['user']['profile'] ?? [],
                            'user_real_name' => $userData['user']['real_name'] ?? null,
                            'user_email' => $userData['user']['profile']['email'] ?? null,
                        ]);
                    }
                }
                
                return $authData;
            }

            // Shopify uses shop info endpoint
            if ($connectorId === 'shopify' && $shop) {
                $response = Http::withoutVerifying()
                    ->withHeaders(['X-Shopify-Access-Token' => $accessToken])
                    ->get("https://{$shop}/admin/api/2024-01/shop.json");
                if ($response->successful()) {
                    $data = $response->json();
                    return $data['shop'] ?? [];
                }
                return ['domain' => $shop, 'myshopify_domain' => $shop];
            }

            switch ($connectorId) {
                case 'linkedin':
                    $response = Http::withoutVerifying()->withToken($accessToken)
                        ->withHeaders(['X-Restli-Protocol-Version' => '2.0.0'])
                        ->get('https://api.linkedin.com/v2/userinfo');
                    return $response->successful() ? $response->json() : [];
                
                default:
                    return [];
            }
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}