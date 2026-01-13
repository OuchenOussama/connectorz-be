<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_connections', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->string('connector_id');
            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->string('token_type')->default('Bearer');
            $table->timestamp('expires_at')->nullable();
            $table->json('scopes');
            $table->enum('status', ['active', 'expired', 'revoked'])->default('active');
            $table->json('connector_metadata')->nullable();
            $table->timestamp('granted_at');
            $table->timestamps();
            
            $table->unique(['user_id', 'connector_id']);
            $table->index(['connector_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_connections');
    }
};