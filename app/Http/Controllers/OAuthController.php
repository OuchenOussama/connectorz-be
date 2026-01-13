<?php

namespace App\Http\Controllers;

use App\Services\OAuthService;
use App\Models\OAuthConnection;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Http;

class OAuthController extends Controller
{
    public function __construct(private OAuthService $oauthService) {}

    public function authorize(Request $request): JsonResponse
    {
        $request->validate([
            'userId' => 'required|string',
            'connectorId' => 'required|string',
            'scopes' => 'required|string',
            'redirectUri' => 'nullable|url',
        ]);

        try {
            $authData = $this->oauthService->generateAuthUrl(
                $request->connectorId,
                $request->userId,
                $request->scopes,
                $request->redirectUri
            );

            return response()->json($authData);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to generate auth URL'], 500);
        }
    }

    public function callback(Request $request): Response
    {
        \Log::info('OAuth Callback Hit', $request->all());
        
        $request->validate([
            'code' => 'required|string',
            'state' => 'required|string',
        ]);

        try {
            $stateData = json_decode(base64_decode($request->state), true);
            \Log::info('State Data', $stateData ?? []);
            
            if (!$stateData || !isset($stateData['user_id'], $stateData['connector_id'])) {
                throw new \Exception('Invalid state parameter');
            }

            $redirectUri = config('app.url') . '/api/oauth/callback';
            
            $tokenData = $this->oauthService->exchangeCodeForTokens(
                $stateData['connector_id'],
                $request->code,
                $redirectUri
            );
            \Log::info('Token Data', $tokenData);

            $scopes = isset($tokenData['scope']) ? explode(' ', $tokenData['scope']) : [];
            if (empty($scopes) && $request->has('scope')) {
                $scopes = explode(' ', $request->input('scope'));
            }
            
            $connection = $this->oauthService->storeConnection(
                $stateData['user_id'],
                $stateData['connector_id'],
                $tokenData,
                $scopes
            );
            \Log::info('Connection Stored', ['id' => $connection->id]);

            $html = '<!DOCTYPE html>
<html>
<head>
    <title>Authorization Complete</title>
</head>
<body>
    <script>
        window.opener.postMessage({ 
            success: true, 
            connectorId: "' . $stateData['connector_id'] . '" 
        }, "*");
        window.close();
    </script>
    <p>Authorization complete. You can close this window.</p>
</body>
</html>';

            return response($html)->header('Content-Type', 'text/html');
        } catch (\Exception $e) {
            \Log::error('OAuth Callback Error', ['error' => $e->getMessage()]);
            $html = '<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
</head>
<body>
    <script>
        window.opener.postMessage({ 
            success: false, 
            error: "' . $e->getMessage() . '" 
        }, "*");
        window.close();
    </script>
    <p>Authorization failed: ' . $e->getMessage() . '</p>
</body>
</html>';

            return response($html, 400)->header('Content-Type', 'text/html');
        }
    }

    public function checkConnection(string $userId, string $connectorId): JsonResponse
    {
        $connection = OAuthConnection::where('user_id', $userId)
            ->where('connector_id', $connectorId)
            ->first();

        if (!$connection) {
            return response()->json([
                'connected' => false,
                'connectorId' => $connectorId,
            ]);
        }

        return response()->json([
            'connected' => true,
            'connectorId' => $connection->connector_id,
            'status' => $connection->status,
            'grantedScopes' => $connection->scopes,
            'grantedAt' => $connection->granted_at,
            'expiresAt' => $connection->expires_at,
            'metadata' => $connection->connector_metadata,
        ]);
    }

    public function listConnections(Request $request, string $userId): JsonResponse
    {
        $query = OAuthConnection::where('user_id', $userId);

        if ($request->has('status')) {
            $query->where('status', $request->status);
        }

        $connections = $query->get()->map(function ($conn) use ($request) {
            $data = [
                'connectorId' => $conn->connector_id,
                'status' => $conn->status,
                'grantedScopes' => $conn->scopes,
                'grantedAt' => $conn->granted_at,
                'expiresAt' => $conn->expires_at,
            ];

            if ($request->boolean('includeMetadata')) {
                $data['metadata'] = $conn->connector_metadata;
            }

            return $data;
        });

        return response()->json([
            'userId' => $userId,
            'connections' => $connections,
            'total' => $connections->count(),
        ]);
    }

    public function revokeConnection(Request $request, string $userId, string $connectorId): JsonResponse
    {
        $connection = OAuthConnection::where('user_id', $userId)
            ->where('connector_id', $connectorId)
            ->first();

        if (!$connection) {
            return response()->json(['error' => 'Connection not found'], 404);
        }

        if ($request->boolean('revokeFromProvider', true)) {
            $this->revokeFromProvider($connectorId, $connection->access_token);
        }

        $connection->update(['status' => 'revoked']);

        return response()->json([
            'success' => true,
            'connectorId' => $connectorId,
            'revokedAt' => now(),
        ]);
    }

    public function updateScopes(Request $request, string $userId, string $connectorId): JsonResponse
    {
        $request->validate(['additionalScopes' => 'required|array']);

        $connection = OAuthConnection::where('user_id', $userId)
            ->where('connector_id', $connectorId)
            ->first();

        if (!$connection) {
            return response()->json(['error' => 'Connection not found'], 404);
        }

        $currentScopes = $connection->scopes ?? [];
        $newScopes = array_unique(array_merge($currentScopes, $request->additionalScopes));
        $scopeString = implode(' ', $newScopes);

        $authData = $this->oauthService->generateAuthUrl(
            $connectorId,
            $userId,
            $scopeString
        );

        return response()->json([
            'requiresReauth' => true,
            'authUrl' => $authData['authUrl'],
            'message' => 'Additional scopes require re-authorization',
        ]);
    }

    private function revokeFromProvider(string $connectorId, string $accessToken): void
    {
        try {
            $revokeUrls = [
                'gmail' => 'https://oauth2.googleapis.com/revoke',
                'linkedin' => 'https://www.linkedin.com/oauth/v2/revoke',
            ];

            if (isset($revokeUrls[$connectorId])) {
                Http::withoutVerifying()->post($revokeUrls[$connectorId], ['token' => $accessToken]);
            }
        } catch (\Exception $e) {
            \Log::warning('Failed to revoke from provider', ['error' => $e->getMessage()]);
        }
    }
}