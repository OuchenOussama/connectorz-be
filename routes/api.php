<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\OAuthController;

Route::prefix('oauth')->group(function () {
    Route::get('/authorize', [OAuthController::class, 'authorize']);
    Route::get('/callback', [OAuthController::class, 'callback']);
    
    Route::get('/connections/{userId}/{connectorId}', [OAuthController::class, 'checkConnection']);
    Route::get('/connections/{userId}', [OAuthController::class, 'listConnections']);
    Route::delete('/connections/{userId}/{connectorId}', [OAuthController::class, 'revokeConnection']);
    Route::patch('/connections/{userId}/{connectorId}/scopes', [OAuthController::class, 'updateScopes']);
});