<?php

declare(strict_types=1);

namespace ThreatIntel\Database;

use PDO;
use PDOException;
use RuntimeException;

class Database
{
    private PDO $connection;

    public function __construct()
    {
        $databaseDirectory = __DIR__ . '/../../../data';

        if (!is_dir($databaseDirectory)) {
            mkdir($databaseDirectory, 0775, true);
        }

        $databasePath = $databaseDirectory . '/threatintel.sqlite';

        try {
            $this->connection = new PDO('sqlite:' . $databasePath);

            $this->connection->setAttribute(
                PDO::ATTR_ERRMODE,
                PDO::ERRMODE_EXCEPTION
            );

            $this->connection->setAttribute(
                PDO::ATTR_DEFAULT_FETCH_MODE,
                PDO::FETCH_ASSOC
            );
        } catch (PDOException $exception) {
            throw new RuntimeException(
                'Unable to connect to the database: ' . $exception->getMessage()
            );
        }
    }

    public function getConnection(): PDO
    {
        return $this->connection;
    }
}
