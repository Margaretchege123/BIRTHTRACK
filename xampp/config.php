<?php
declare(strict_types=1);

function birthtrack_db(): PDO
{
    $host = getenv('BIRTHTRACK_DB_HOST') ?: '127.0.0.1';
    $name = getenv('BIRTHTRACK_DB_NAME') ?: 'birthtrack';
    $user = getenv('BIRTHTRACK_DB_USER') ?: 'root';
    $password = getenv('BIRTHTRACK_DB_PASSWORD');

    $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";
    return new PDO($dsn, $user, $password === false ? '' : $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}
