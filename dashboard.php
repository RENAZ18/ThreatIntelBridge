<?php

declare(strict_types=1);

require_once __DIR__ . '/lib/ThreatIntel/Database/Database.php';
require_once __DIR__ . '/lib/ThreatIntel/Database/ThreatEventQueryRepository.php';
require_once __DIR__ . '/lib/ThreatIntel/Services/PriorityCalculator.php';

$priorityCalculator = new \ThreatIntel\Services\PriorityCalculator();

$database = new \ThreatIntel\Database\Database();

$repository = new \ThreatIntel\Database\ThreatEventQueryRepository(
    $database->getConnection()
);

$search = trim($_GET['search'] ?? '');
$severity = trim($_GET['severity'] ?? '');
$source = trim($_GET['source'] ?? '');
$priorityFilter = trim($_GET['priority'] ?? '');

$events = $repository->findAll(
    $search !== '' ? $search : null,
    $severity !== '' ? $severity : null,
    $source !== '' ? $source : null
);

$totalthreats = count($events);

$UrgentCount = 0;
$highCount = 0;
$mediumCount = 0;
$lowCount = 0;


function formatThreatDate(?string $date): string
{
    if ($date === null || trim($date) === '') {
        return 'Unknown';
    }

    try {
        return (new DateTimeImmutable($date))->format('Y-m-d');
    } catch (Exception) {
        return $date;
    }
}

foreach ($events as $event) {
    $priority = $priorityCalculator->calculate(
        $event['sources'] ?? [],
        $event['severity'] ?? null,
        $event['cvss'] !== null ? (float) $event['cvss'] : null,
        $event['first_seen'] ?? null
    );

    switch ($priority['priority']) {
        case 'Urgent':
            $urgentCount++;
            break;

        case 'High':
            $highCount++;
            break;

        case 'Medium':
            $mediumCount++;
            break;

        default:
            $lowCount++;
    }
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Open Threat Hub</title>

    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            color: #111827;
        }

        header {
            background: #111827;
            color: white;
            padding: 24px;
        }

        header h1 {
            margin: 0 0 6px;
        }

        main {
            width: min(1100px, 92%);
            margin: 28px auto;
        }

        form {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr auto;
            gap: 12px;
            margin-bottom: 24px;
        }

        input,
        select,
        button {
            padding: 11px;
            border: 1px solid #d1d5db;
            border-radius: 7px;
            font-size: 15px;
        }

        button {
            background: #2563eb;
            color: white;
            border: 0;
            cursor: pointer;
        }

        .summary {
            margin-bottom: 18px;
            color: #4b5563;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 18px;
            text-align: center;
            box-shadow: 0 2px 7px rgba(0,0,0,.08);
        }

        .summary-card.total {
            border-top: 4px solid #2563eb;
        }
        
        .summary-card.urgent {
            border-top: 4px solid #dc2626;
        }
        
        .summary-card.high {
            border-top: 4px solid #ea580c;
        }
        
        .summary-card.medium {
            border-top: 4px solid #eab308;
        }
        
        .summary-card.low {
            border-top: 4px solid #16a34a;
        }
        
        .summary-card h3 {
            margin: 0;
            font-size: 15px;
            color: #6b7280;
        }
        
        .summary-card .value {
            margin-top: 10px;
            font-size: 32px;
            font-weight: bold;
        }


        
        .priority {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
        }

        .priority-urgent {
            background: #dc2626;
            color: white;
        }

        .priority-high {
            background: #ea580c;
            color: white;
        }

        .priority-medium {
            background: #eab308;
            color: black;
        }
        
        .priority-low {
            background: #16a34a;
            color: white;
        }

        .card {
            background: white;
            border-radius: 10px;
            margin-bottom: 16px;
            box-shadow: 0 2px 7px rgba(0, 0, 0, 0.08);
            transition: transform 0.2s, box-shadow 0.2s;
            height: 100%;
        }


        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 14px rgba(0, 0, 0, 0.12);
        }
        
        .card-link {
            display: flex;
            flex-direction: column;
            height: 100%;
            box-sizing: border-box;
            padding: 20px;
            color: inherit;
            text-decoration: none;
        }

        .card h2 {
            margin-top: 0;
            font-size: 18px;
            line-height: 1.4;
        }

        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 18px;
        }

        .metadata {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 12px 0;
        }

        .badge {
            background: #e5e7eb;
            padding: 5px 9px;
            border-radius: 12px;
            font-size: 13px;
        }

        .critical {
            background: #fee2e2;
        }

        .high {
            background: #ffedd5;
        }

        .medium {
            background: #fef3c7;
        }

        .low {
            background: #dcfce7;
        }

        .view-details {
            margin-top: auto;
            padding-top: 16px;
            color: #2563eb;
            font-weight: 600;
            font-size: 14px;
        }

        .empty {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
        }

        @media (max-width: 760px) {
            form {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>
<header>
    <h1>Open Threat Hub</h1>
    <div>Unified and correlated security advisories</div>
</header>

<main>
<form method="get">
    <input
        type="text"
        name="search"
        placeholder="Search by CVE, title, or description"
        value="<?= htmlspecialchars($search) ?>"
    >

    <select name="severity">
        <option value="">All severities</option>

        <?php foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $level): ?>
            <option
                value="<?= $level ?>"
                <?= strtoupper($severity) === $level ? 'selected' : '' ?>
            >
                <?= $level ?>
            </option>
        <?php endforeach; ?>
    </select>

    <select name="priority">
        <option value="">All priorities</option>

        <?php foreach (['Urgent', 'High', 'Medium', 'Low'] as $level): ?>
            <option
                value="<?= $level ?>"
                <?= $priorityFilter === $level ? 'selected' : '' ?>
            >
                <?= $level ?>
            </option>
        <?php endforeach; ?>
    </select>

    <select name="source">
        <option value="">All sources</option>

        <?php foreach (['CISA', 'NVD', 'GitHub'] as $sourceName): ?>
            <option
                value="<?= $sourceName ?>"
                <?= $source === $sourceName ? 'selected' : '' ?>
            >
                <?= $sourceName ?>
            </option>
        <?php endforeach; ?>
    </select>

    <button type="submit">Filter</button>
</form>

    <div class="summary-cards">
    
        <div class="summary-card">
            <h3>Total Threats</h3>
            <div class="value"><?= $totalthreats ?></div>
        </div>
    
        <div class="summary-card">
            <h3>🔴 Urgent</h3>
            <div class="value"><?= $urgentCount ?></div>
        </div>
    
        <div class="summary-card">
            <h3>🟠 High</h3>
            <div class="value"><?= $highCount ?></div>
        </div>
    
        <div class="summary-card">
            <h3>🟡 Medium</h3>
            <div class="value"><?= $mediumCount ?></div>
        </div>
    
        <div class="summary-card">
            <h3>🟢 Low</h3>
            <div class="value"><?= $lowCount ?></div>
        </div>
    
    </div>

    <?php if ($events === []): ?>
        <div class="empty">
            No threat events matched your filters.
        </div>
    <?php endif; ?>
    
    <div class="cards-grid">
    <?php foreach ($events as $event): ?>
    <?php
    $severityClass = strtolower($event['severity'] ?? '');
    
    $priority = $priorityCalculator->calculate(
        $event['sources'] ?? [],
        $event['severity'] ?? null,
        $event['cvss'] !== null ? (float) $event['cvss'] : null,
        $event['first_seen'] ?? null
    );

    if (
        $priorityFilter !== ''
        && $priority['priority'] !== $priorityFilter
    ) {
        continue;
    }
    ?>

    <article class="card">
        <a
            class="card-link"
            href="event.php?id=<?= (int) $event['id'] ?>"
        >
            <h2>
                <?= htmlspecialchars($event['cve_id']) ?>
                -
                <?= htmlspecialchars($event['title']) ?>
            </h2>
    
            <div class="metadata">
                <?php if (!empty($event['severity'])): ?>
                    <span class="badge <?= htmlspecialchars($severityClass) ?>">
                        Severity: <?= htmlspecialchars($event['severity']) ?>
                    </span>
                <?php endif; ?>

                <span class="priority priority-<?= strtolower($priority['priority']) ?>">
                    Priority: <?= htmlspecialchars($priority['priority']) ?>
                    (<?= (int) $priority['score'] ?>)
                </span>
    
                <?php if ($event['cvss'] !== null): ?>
                    <span class="badge">
                        CVSS: <?= htmlspecialchars((string) $event['cvss']) ?>
                    </span>
                <?php endif; ?>
    
                <span class="badge">
                    Sources: <?= htmlspecialchars($event['sources'] ?? 'Unknown') ?>
                </span>
            </div>
    
            <div class="view-details">
                View threat details →
            </div>
    
            <small>
                Last seen:
                <?= htmlspecialchars(formatThreatDate($event['last_seen'] ?? null)) ?>
            </small>
        </a>
    </article>
    <?php endforeach; ?>
    </div>
</main>
</body>
</html>
