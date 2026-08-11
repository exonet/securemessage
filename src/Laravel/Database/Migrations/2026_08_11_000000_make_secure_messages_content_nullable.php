<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations. The content column is null for file messages: their encrypted contents
     * are stored on the configured files disk instead of in the database.
     */
    public function up(): void
    {
        Schema::table('secure_messages', function (Blueprint $table) {
            $table->text('content')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations. Note: reversing fails when file messages (rows with a null content
     * column) exist in the table.
     */
    public function down(): void
    {
        Schema::table('secure_messages', function (Blueprint $table) {
            $table->text('content')->nullable(false)->change();
        });
    }
};
