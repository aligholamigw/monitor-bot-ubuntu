<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
require dirname(__DIR__) . '/src/bootstrap.php';

$mode = $argv[1] ?? 'check';
try {
    [$config, $store, $api] = application(45);
    if (($config['telegram_mode'] ?? '') !== 'polling') {
        throw new RuntimeException('Expected telegram_mode=polling.');
    }
    // Apply the same route as the application, including a configured SOCKS proxy.
    $app = new App($config, $store, $api);
    if ($mode === 'switch') {
        $api->telegram('deleteWebhook', ['drop_pending_updates' => false]);
        $info = $api->telegram('getWebhookInfo', []);
        if (($info['result']['url'] ?? null) !== '') { throw new RuntimeException('Telegram still reports an active webhook.'); }
        echo "Telegram webhook removed. Pending updates were preserved.\n";
        exit(0);
    }
    if (!is_array($api->monitor()['configs'] ?? null)) { throw new RuntimeException('Invalid Status response.'); }
    echo "Monitoring Status API OK.\n";
    if (!is_array($api->liveMeta()['workers'] ?? null)) { throw new RuntimeException('Invalid Live response.'); }
    echo "Monitoring Live API OK.\n";
    foreach ($config['domains'] as $domain) {
        $records = $api->records($domain);
        if (count(array_filter($records, fn($record) => ($record['name'] ?? '') === $domain && ($record['type'] ?? '') === 'A')) !== 1
            || array_filter($records, fn($record) => in_array($record['type'] ?? '', ['AAAA', 'CNAME'], true))) {
            throw new RuntimeException('Expected exactly one A record and no AAAA/CNAME for ' . $domain);
        }
    }
    echo "Cloudflare DNS read OK.\n";
    $api->telegram('getMe', []);
    $info = $api->telegram('getWebhookInfo', []);
    echo "Telegram API OK.\n";
    if (!empty($info['result']['url'])) {
        fwrite(STDERR, "Telegram already has an active webhook. Stop the old cPanel cron, then rerun with --switch-webhook.\n");
        exit(12);
    }
} catch (Throwable $error) {
    $reason = $error instanceof RuntimeException ? $error->getMessage() : get_class($error);
    fwrite(STDERR, "Preflight failed: {$reason}\n");
    exit(1);
}
