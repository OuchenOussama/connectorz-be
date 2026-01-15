<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OAuthConnection extends Model
{
    protected $table = 'oauth_connections';
    
    protected $fillable = [
        'user_id',
        'connector_id',
        'account_identifier',
        'access_token',
        'refresh_token',
        'token_type',
        'expires_at',
        'scopes',
        'status',
        'connector_metadata',
        'granted_at',
    ];

    protected $casts = [
        'scopes' => 'array',
        'connector_metadata' => 'array',
        'expires_at' => 'datetime',
        'granted_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function isExpired(): bool
    {
        return $this->expires_at && $this->expires_at->isPast();
    }

    public function isActive(): bool
    {
        return $this->status === 'active' && !$this->isExpired();
    }
}