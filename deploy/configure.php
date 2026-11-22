<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }

function privateWrite(string $file, string $body): void
{
    $temp = tempnam(dirname($file), '.monitor-');
    if ($temp === false) { throw new RuntimeException('Cannot create temporary settings file.'); }
    try {
        if (!chmod($temp, 0600) || file_put_contents($temp, $body) !== strlen($body) || !rename($temp, $file)) {
            throw new RuntimeException('Cannot write the private deployment file.');
        }
    } finally {
        if (is_file($temp)) { unlink($temp); }
    }
}

try {
    if (($argv[1] ?? '') === 'import-state') {
        $state = json_decode(file_get_contents($argv[2]), true, 128, JSON_THROW_ON_ERROR);
        if (!is_array($state) || ($state['version'] ?? null) !== 1 || !is_array($state['pool'] ?? null)
            || !is_array($state['scan'] ?? null) || !is_array($state['targets'] ?? null)) {
            throw new RuntimeException('Invalid Monitor Bot state file.');
        }
        $state['paused'] = true;
        $state['dry_run'] = true;
        $state['scan']['paused'] = true;
        $state['sample_floor'] = time();
        $state['last_monitor_poll'] = 0;
        $state['monitor_proxy'] = 'config';
        foreach ($state['targets'] as &$target) { $target['samples'] = []; }
        unset($target);
        privateWrite($argv[3], json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
        exit(0);
    }
    if (($argv[1] ?? '') !== 'new') { exit(2); }
    $config = require dirname(__DIR__) . '/config.example.php';
    $values = explode("\0", (string)stream_get_contents(STDIN));
    if (count($values) !== 7) { throw new RuntimeException('Missing deployment settings.'); }
    [$monitor, $telegram, $admin, $zone, $cloudflare, $template, $proxy] = $values;
    $url = parse_url($monitor);
    if (!is_array($url) || !isset($url['host']) || !in_array($url['scheme'] ?? '', ['http', 'https'], true)
        || !str_ends_with($url['path'] ?? '', '/status') || !preg_match('/^\d+:[A-Za-z0-9_-]+$/D', $telegram)
        || !preg_match('/^[1-9]\d{0,19}$/D', $admin) || !preg_match('/^[a-f0-9]{32}$/iD', $zone)
        || $cloudflare === '' || $template === '') {
        throw new RuntimeException('Check the Status URL, Telegram credentials, Cloudflare zone and VLESS template.');
    }
    require_once dirname(__DIR__) . '/src/app.php';
    VlessTemplate::source($template, '104.16.0.1', 'setup-validation');
    if ($proxy !== '' && App::normalizeProxy($proxy, true) === null) {
        throw new RuntimeException('Invalid SOCKS5 proxy URL.');
    }
    $config = array_replace($config, [
        'telegram_mode' => 'polling', 'data_dir' => '/var/lib/monitor-bot',
        'monitor_url' => $monitor, 'telegram_token' => $telegram, 'telegram_chat_id' => $admin,
        'admin_user_ids' => [$admin], 'cloudflare_zone_id' => $zone, 'cloudflare_token' => $cloudflare,
        'live_template' => $template, 'monitor_socks_proxy' => $proxy,
    ]);
    privateWrite($argv[2], "<?php\ndeclare(strict_types=1);\nreturn " . var_export($config, true) . ";\n");
} catch (Throwable $error) {
    $reason = $error instanceof RuntimeException || $error instanceof InvalidArgumentException
        ? $error->getMessage() : get_class($error);
    fwrite(STDERR, "Configuration failed: {$reason}\n");
    exit(1);
}
