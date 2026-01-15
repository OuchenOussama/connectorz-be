<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE oauth_connections DROP CONSTRAINT IF EXISTS oauth_connections_user_id_connector_id_key');
    }

    public function down(): void
    {
        Schema::table('oauth_connections', function (Blueprint $table) {
            $table->unique(['user_id', 'connector_id']);
        });
    }
};