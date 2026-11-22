<?php
declare(strict_types=1);
require_once __DIR__ . '/app.php';
function application(float $networkBudget = 45): array
{
    $file = getenv('MONITOR_BOT_CONFIG') ?: dirname(__DIR__) . '/config.php';
    if (!is_file($file)) {
        throw new RuntimeException('Copy config.example.php to config.php and fill settings.');
    }
    $config = require $file;
    $required = ['monitor_url', 'cloudflare_token', 'cloudflare_zone_id', 'telegram_token', 'telegram_chat_id'];
    if (($config['telegram_mode'] ?? 'webhook') !== 'polling') { $required[] = 'webhook_secret'; }
    foreach ($required as $key) {
        if (empty($config[$key]) || str_contains((string)$config[$key], 'CHANGE_ME')) {
            throw new RuntimeException('Missing configuration: ' . $key);
        }
    }
    if (count($config['domains']) !== 2 || count(array_unique($config['domains'])) !== 2
        || !in_array($config['operator_policy'], ['any', 'all'], true)
        || !in_array($config['failure_threshold'], [2, 3], true)
        || !$config['admin_user_ids'] || array_filter($config['admin_user_ids'], fn($id) => !ctype_digit((string)$id))) {
        throw new RuntimeException('Invalid domains, operators, threshold or admin IDs.');
    }
    if (($config['require_live_preflight'] ?? true) && (empty($config['live_template']) || str_contains($config['live_template'], 'CHANGE_ME'))) {
        throw new RuntimeException('Missing live_template: enter the full private VLESS link.');
    }
    $liveWorkers = $config['live_workers'] ?? []; $liveChecks = $config['live_checks'] ?? [];
    sort($liveWorkers); sort($liveChecks);
    if ($liveWorkers !== ['mci-thr', 'mkh-thr', 'mtn-asiatech', 'mtn-mashhad'] || $liveChecks !== ['download', 'jitter', 'upload']) {
        throw new RuntimeException('Live testing requires the four Iranian workers and upload/download/jitter.');
    }
    return [$config, new Store($config['data_dir']), new Network($config, $networkBudget)];
}
