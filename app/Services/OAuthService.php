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
            'auth_url' => 'https://{shop}.myshopify.com/admin/oauth/authorize',
            'token_url' => 'https://{shop}.myshopify.com/admin/oauth/access_token',
            'client_id' => 'SHOPIFY_CLIENT_ID',
            'client_secret' => 'SHOPIFY_CLIENT_SECRET',
        ],
        'facebook' => [
            'auth_url' => 'https://www.facebook.com/v18.0/dialog/oauth',
            'token_url' => 'https://graph.facebook.com/v18.0/oauth/access_token',
            'client_id' => 'FACEBOOK_CLIENT_ID',
            'client_secret' => 'FACEBOOK_CLIENT_SECRET',
        ],
    ];

    public function generateAuthUrl(string $connectorId, string $userId, string $scopes, ?string $redirectUri = null): array
    {
        if (!isset($this->connectors[$connectorId])) {
            throw new \InvalidArgumentException("Unsupported connector: {$connectorId}");
        }

        $connector = $this->connectors[$connectorId];
        $state = base64_encode(json_encode([
            'user_id' => $userId,
            'connector_id' => $connectorId,
            'csrf_token' => Str::random(32),
        ]));

        $params = [
            'client_id' => env($connector['client_id']),
            'redirect_uri' => $redirectUri ?: config('app.url') . '/api/oauth/callback',
            'scope' => $scopes,
            'response_type' => 'code',
            'state' => $state,
        ];

        $authUrl = $connector['auth_url'] . '?' . http_build_query($params);

        return [
            'authUrl' => $authUrl,
            'state' => $state,
            'connectorId' => $connectorId,
        ];
    }

    public function exchangeCodeForTokens(string $connectorId, string $code, string $redirectUri): array
    {
        if (!isset($this->connectors[$connectorId])) {
            throw new \InvalidArgumentException("Unsupported connector: {$connectorId}");
        }

        $connector = $this->connectors[$connectorId];
        
        $response = Http::withoutVerifying()->asForm()->post($connector['token_url'], [
            'client_id' => env($connector['client_id']),
            'client_secret' => env($connector['client_secret']),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirectUri,
        ]);

        if (!$response->successful()) {
            throw new \Exception("Failed to exchange code for tokens: " . $response->body());
        }

        return $response->json();
    }

    public function storeConnection(string $userId, string $connectorId, array $tokenData, array $scopes): OAuthConnection
    {
        $metadata = $this->getConnectorMetadata($connectorId, $tokenData['access_token']);
        $accountId = $this->extractAccountIdentifier($connectorId, $metadata);

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
        return match($connectorId) {
            'gmail' => $metadata['email'] ?? $metadata['id'] ?? null,
            'linkedin' => $metadata['sub'] ?? $metadata['id'] ?? null,
            'facebook' => $metadata['id'] ?? null,
            'stripe' => $metadata['stripe_user_id'] ?? null,
            default => $metadata['id'] ?? $metadata['email'] ?? null,
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

    private function getConnectorMetadata(string $connectorId, string $accessToken): array
    {
        try {
            switch ($connectorId) {
                case 'gmail':
                    $response = Http::withoutVerifying()->withToken($accessToken)
                        ->get('https://www.googleapis.com/oauth2/v2/userinfo');
                    return $response->successful() ? $response->json() : [];
                
                case 'linkedin':
                    $response = Http::withoutVerifying()->withToken($accessToken)
                        ->withHeaders(['X-Restli-Protocol-Version' => '2.0.0'])
                        ->get('https://api.linkedin.com/v2/userinfo');
                    return $response->successful() ? $response->json() : [];
                
                case 'facebook':
                    $response = Http::withoutVerifying()->withToken($accessToken)
                        ->get('https://graph.facebook.com/me');
                    return $response->successful() ? $response->json() : [];
                
                default:
                    return [];
            }
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}