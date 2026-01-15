<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_connections', function (Blueprint $table) {
            $table->string('account_identifier')->nullable()->after('connector_id');
            $table->unique(['user_id', 'connector_id', 'account_identifier'], 'oauth_user_connector_account_unique');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_connections', function (Blueprint $table) {
            $table->dropUnique('oauth_user_connector_account_unique');
            $table->dropColumn('account_identifier');
        });
    }
};