<?php

declare(strict_types=1);

namespace ThreatIntel\Database;

use PDO;

class ThreatEventQueryRepository
{
    public function __construct(
        private PDO $connection
    ) {
    }

    public function findAll(
        ?string $search = null,
        ?string $severity = null,
        ?string $source = null
    ): array {
        $conditions = [];
        $parameters = [];

        $sql = <<<SQL
            SELECT
                threat_events.id,
                threat_events.cve_id,
                threat_events.title,
                threat_events.description,
                threat_events.severity,
                threat_events.cvss,
                threat_events.first_seen,
                threat_events.last_seen,
                GROUP_CONCAT(
                    DISTINCT event_sources.source
                ) AS sources
            FROM threat_events
            LEFT JOIN event_sources
                ON event_sources.threat_event_id = threat_events.id
        SQL;

        if ($search !== null && $search !== '') {
            $conditions[] = <<<SQL
                (
                    threat_events.cve_id LIKE :search
                    OR threat_events.title LIKE :search
                    OR threat_events.description LIKE :search
                )
            SQL;

            $parameters[':search'] = '%' . $search . '%';
        }

        if ($severity !== null && $severity !== '') {
            $conditions[] = 'threat_events.severity = :severity';

            $parameters[':severity'] = strtoupper($severity);
        }

        if ($source !== null && $source !== '') {
            $conditions[] = <<<SQL
                EXISTS (
                    SELECT 1
                    FROM event_sources AS source_filter
                    WHERE source_filter.threat_event_id = threat_events.id
                    AND source_filter.source = :source
                )
            SQL;

            $parameters[':source'] = $source;
        }

        if ($conditions !== []) {
            $sql .= "\nWHERE " . implode(
                "\nAND ",
                $conditions
            );
        }

        $sql .= <<<SQL

            GROUP BY threat_events.id
            ORDER BY
                CASE UPPER(threat_events.severity)
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END DESC,
                threat_events.cvss DESC,
                threat_events.last_seen DESC
        SQL;

        $statement = $this->connection->prepare($sql);
        $statement->execute($parameters);

        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): ?array
    {
        $sql = <<<SQL
            SELECT
                threat_events.id,
                threat_events.cve_id,
                threat_events.title,
                threat_events.description,
                threat_events.severity,
                threat_events.cvss,
                threat_events.first_seen,
                threat_events.last_seen,
                threat_events.created_at,
                threat_events.updated_at,
                GROUP_CONCAT(
                    DISTINCT event_sources.source
                ) AS sources,
                GROUP_CONCAT(
                    event_sources.source
                    || '|'
                    || COALESCE(event_sources.source_url, ''),
                    '||'
                ) AS source_links
            FROM threat_events
            LEFT JOIN event_sources
                ON event_sources.threat_event_id = threat_events.id
            WHERE threat_events.id = :id
            GROUP BY threat_events.id
            LIMIT 1
        SQL;

        $statement = $this->connection->prepare($sql);

        $statement->execute([
            ':id' => $id,
        ]);

        $event = $statement->fetch(PDO::FETCH_ASSOC);

        return $event !== false ? $event : null;
    }
}
