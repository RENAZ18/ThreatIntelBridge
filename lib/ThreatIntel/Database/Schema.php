<?php

declare(strict_types=1);

namespace ThreatIntel\Database;

use PDO;

class Schema
{
    public static function create(PDO $connection): void
    {
        $connection->exec(
            '
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                cvss REAL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            '
        );

        $connection->exec(
            '
            CREATE TABLE IF NOT EXISTS event_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_event_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT,
                published_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(threat_event_id, source),
                FOREIGN KEY(threat_event_id)
                    REFERENCES threat_events(id)
                    ON DELETE CASCADE
            )
            '
        );
    }
}
