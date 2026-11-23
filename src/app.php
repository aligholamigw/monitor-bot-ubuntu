<?php
declare(strict_types=1);
require_once __DIR__ . '/live.php';
require_once __DIR__ . '/bot-ui.php';

interface Gateway
{
    public function monitor(): array;
    public function records(string $domain): array;
    public function patch(string $id, string $ip): void;
    public function telegram(string $method, array $data): array;
    public function liveMeta(): array;
    public function liveCreate(array $body): array;
    public function liveJob(string $id): array;
}

final class HttpFailure extends RuntimeException
{
    public function __construct(public int $status, public int $retryAfter = 0, public int $curlCode = 0)
    {
        parent::__construct($curlCode ? "cURL {$curlCode}" : "HTTP {$status}");
    }
}

final class Network implements Gateway
{
    private float $deadline;
    private ?string $monitorProxy = null;
    public function __construct(private array $config, float $budget = 45) { $this->deadline = microtime(true) + $budget; }
    public function setMonitorProxy(?string $proxy): void { $this->monitorProxy = $proxy; }
    private function request(string $url, string $method = 'GET', ?array $body = null, array $headers = [], bool $monitor = false): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL extension is required.');
        }
        $remaining = (int)(($this->deadline - microtime(true)) * 1000);
        if ($remaining < 200) { throw new RuntimeException('Network time budget exhausted.'); }
        $curl = curl_init($url);
        $retryAfter = 0;
        $options = [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT_MS => min(10000, $remaining), CURLOPT_FOLLOWLOCATION => false, CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/json', 'Content-Type: application/json'], $headers),
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION => static function($ch, string $header) use (&$retryAfter): int {
                if (preg_match('/^Retry-After:\s*(\d+)/i', $header, $m)) { $retryAfter = min(86400, (int)$m[1]); }
                return strlen($header);
            }];
        if ($monitor) {
            $options[CURLOPT_PROXY] = $this->monitorProxy ?? '';
            $options[CURLOPT_NOPROXY] = '';
        }
        curl_setopt_array($curl, $options);
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        }
        $raw = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $curlCode = curl_errno($curl);
        $failed = $raw === false;
        curl_close($curl);
        // Do not log URLs, headers or response bodies: they can contain credentials.
        if ($failed || $status < 200 || $status >= 300) {
            throw new HttpFailure((int)$status, $retryAfter, $curlCode);
        }
        $data = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new RuntimeException('Invalid API response.');
        }
        return $data;
    }
    public function monitor(): array { return $this->request($this->config['monitor_url'], monitor: true); }
    private function liveUrl(): string
    {
        $url = preg_replace('~/status(?:\?.*)?$~', '/live', $this->config['monitor_url']);
        if ($url === $this->config['monitor_url']) { throw new RuntimeException('Invalid monitoring status URL.'); }
        return $url;
    }
    public function liveMeta(): array { return $this->request($this->liveUrl(), monitor: true); }
    public function liveCreate(array $body): array { return $this->request($this->liveUrl(), 'POST', $body, monitor: true); }
    public function liveJob(string $id): array { return $this->request($this->liveUrl() . '/' . rawurlencode($id), monitor: true); }
    private function cf(string $path, string $method = 'GET', ?array $body = null): array
    {
        $data = $this->request('https://api.cloudflare.com/client/v4/zones/' . rawurlencode($this->config['cloudflare_zone_id']) . '/dns_records' . $path,
            $method, $body, ['Authorization: Bearer ' . $this->config['cloudflare_token']]);
        if (($data['success'] ?? false) !== true) {
            throw new RuntimeException('Cloudflare rejected the operation.');
        }
        return $data;
    }
    public function records(string $domain): array
    {
        $data = $this->cf('?name=' . rawurlencode($domain) . '&per_page=100');
        if (($data['result_info']['total_pages'] ?? 1) > 1) {
            throw new RuntimeException('Too many DNS records for ' . $domain);
        }
        return $data['result'];
    }
    public function patch(string $id, string $ip): void
    {
        // Change content only; preserve TTL, proxy mode and other record settings.
        $data = $this->cf('/' . rawurlencode($id), 'PATCH', ['content' => $ip]);
        if (($data['result']['content'] ?? '') !== $ip) {
            throw new RuntimeException('Cloudflare did not confirm requested content.');
        }
    }
    public function telegram(string $method, array $data): array
    {
        $response = $this->request('https://api.telegram.org/bot' . $this->config['telegram_token'] . '/' . $method, 'POST', $data);
        if (($response['ok'] ?? false) !== true) {
            throw new RuntimeException('Telegram rejected the operation.');
        }
        return $response;
    }
}

final class Store
{
    private $lock;
    public function __construct(private string $dir)
    {
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Cannot create data directory.');
        }
    }
    public function acquire(): void
    {
        $this->lock = fopen($this->dir . '/app.lock', 'c');
        if (!$this->lock || !flock($this->lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('BUSY');
        }
    }
    public function read(array $config): array
    {
        $file = $this->dir . '/state.json';
        if (is_file($file)) {
            $data = json_decode(file_get_contents($file), true, 128, JSON_THROW_ON_ERROR);
            if (!is_array($data) || ($data['version'] ?? 0) !== 1) {
                throw new RuntimeException('State is invalid; restore backup, do not reset automatically.');
            }
            return $data;
        }
        return ['version' => 1, 'paused' => $config['initial_paused'], 'dry_run' => $config['initial_dry_run'],
            'threshold' => $config['failure_threshold'], 'pool' => [], 'targets' => [], 'outbox' => [],
            'alerts' => [], 'updates' => [], 'last_run' => 0, 'sample_floor' => time()];
    }
    public function save(array $data): void
    {
        $file = $this->dir . '/state.json';
        $tmp = $this->dir . '/state.' . bin2hex(random_bytes(6)) . '.tmp';
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        $handle = fopen($tmp, 'xb');
        if (!$handle) { throw new RuntimeException('Cannot create state file.'); }
        chmod($tmp, 0600);
        try {
            if (fwrite($handle, $json) !== strlen($json) || !fflush($handle)) {
                throw new RuntimeException('Cannot persist state.');
            }
            if (function_exists('fsync') && !fsync($handle)) { throw new RuntimeException('Cannot sync state.'); }
        } finally { fclose($handle); }
        if (!rename($tmp, $file)) { throw new RuntimeException('Cannot replace state file.'); }
    }
    public function __destruct()
    {
        if (is_resource($this->lock)) { flock($this->lock, LOCK_UN); fclose($this->lock); }
    }
}

final class App
{
    use LiveOperations;
    use BotUi;
    public array $state;
    public function __construct(public array $config, private Store $store, private Gateway $api)
    {
        $store->acquire();
        $this->state = $store->read($config);
        $this->initLive();
        $this->applyProxy();
    }
    public function save(): void { $this->store->save($this->state); }
    private function target(string $domain): void
    {
        $this->state['targets'][$domain] ??= ['samples' => [], 'changed_at' => 0, 'not_before' => 0, 'pending' => null, 'current_ip' => null];
    }
    public function queue(string $text, ?string $key = null, int $repeat = 0): void
    {
        $now = time();
        if ($key !== null && isset($this->state['alerts'][$key]) && $now - $this->state['alerts'][$key] < $repeat) { return; }
        if ($key !== null) { $this->state['alerts'][$key] = $now; }
        // Bound backlog if Telegram is unavailable for a long time.
        if (count($this->state['outbox']) >= 150) { array_shift($this->state['outbox']); }
        $this->state['outbox'][] = $text;
    }
    public function flush(): void
    {
        $this->save();
        for ($i = 0; $i < 4 && $this->state['outbox']; $i++) {
            try {
                $this->deliver($this->state['outbox'][0]);
            } catch (Throwable $e) { error_log('Telegram delivery failed; queued for next run.'); break; }
            array_shift($this->state['outbox']);
            $this->save();
        }
    }
    private function alert(string $key, string $text): void { $this->queue($text, $key, $this->config['alert_repeat_seconds']); }
    public function poolWarning(): void
    {
        $count = count(array_filter($this->state['pool'], fn($p) => $p['status'] === 'available'));
        if ($count <= $this->config['low_pool_threshold']) {
            $level = $count === 0 ? 'empty' : 'low';
            $this->alert('pool-' . $level, ($count === 0 ? '⛔ مخزن IP خالی است؛ تعویض ممکن نیست.' : "⚠️ موجودی مخزن کم است: {$count} IP آماده.") . "\nبرای افزودن، از «مخزن IP» استفاده کنید.");
        } else { unset($this->state['alerts']['pool-low'], $this->state['alerts']['pool-empty']); }
    }
    public function command(array $update): void
    {
        $this->handleUpdate($update);
    }
    private function executeCommand(string $cmd, array $parts): string
    {
        $reply = '';
        switch ($cmd) {
            case '/scan': case '/scanstatus': case '/scanstop': case '/scanresume':
                $reply = $this->scanCommand($cmd, $parts); break;
            case '/remove':
                $ip = $parts[0] ?? '';
                if (($this->state['pool'][$ip]['status'] ?? '') !== 'available') { $reply = 'این IP در مخزن آماده نیست.'; break; }
                unset($this->state['pool'][$ip]); $reply = 'IP از مخزن آماده حذف شد.'; break;
            case '/pool':
                $counts = array_count_values(array_column($this->state['pool'], 'status'));
                $groups = ['complete' => [], 'unknown' => [], 'fallback' => []];
                foreach ($this->state['pool'] as $ip => $entry) {
                    if ($entry['status'] === 'available') { $groups[$this->poolDownloadGroup($entry)][] = $ip; }
                }
                $reply = 'آماده ' . ($counts['available'] ?? 0) . ' · رزرو ' . ($counts['reserved'] ?? 0)
                    . ' · در حال تست ' . ($counts['testing'] ?? 0) . ' · ردشده ' . ($counts['rejected'] ?? 0)
                    . ' · مصرف‌شده/بازنشسته ' . (($counts['used'] ?? 0) + ($counts['retired'] ?? 0));
                foreach (['complete' => '🟢 دانلود تأییدشده · اولویت اول', 'unknown' => '⚪ وضعیت دانلود نامشخص',
                    'fallback' => '🟡 گروه ذخیره · خطای تست دانلود'] as $group => $label) {
                    $ips = $groups[$group];
                    $reply .= "\n\n{$label} (" . count($ips) . ')';
                    if ($ips) { $reply .= "\n" . implode("\n", array_slice($ips, 0, 15)); }
                    if (count($ips) > 15) { $reply .= "\n… و " . (count($ips) - 15) . ' IP دیگر'; }
                }
                break;
            case '/threshold':
                if (!in_array($parts[0] ?? '', ['2', '3'], true)) { $reply = 'آستانه را از دکمه‌های ۲ یا ۳ نتیجهٔ قرمز انتخاب کنید.'; break; }
                $this->state['threshold'] = (int)$parts[0];
                $this->state['sample_floor'] = time();
                foreach ($this->state['targets'] as &$target) { $target['samples'] = []; } unset($target);
                $reply = 'آستانه تنظیم شد؛ شمارش قرمزها از تست‌های بعدی شروع می‌شود.'; break;
            case '/pause': $this->state['paused'] = true; $reply = '⏸ تعویض متوقف شد؛ بررسی وضعیت ادامه دارد.'; break;
            case '/resume':
                $this->state['paused'] = false;
                $this->state['sample_floor'] = time();
                foreach ($this->state['targets'] as &$target) { $target['samples'] = []; } unset($target);
                $reply = '▶️ بررسی و شمارش از تست بعدی ادامه یافت. حالت: ' . ($this->state['dry_run'] ? 'شبیه‌سازی' : 'واقعی'); break;
            case '/dryrun': $this->state['dry_run'] = true; $reply = '🧪 شبیه‌سازی فعال شد؛ عملیات DNS قبلاً ارسال‌شده همچنان تطبیق داده می‌شود.'; break;
            case '/live':
                $this->state['dry_run'] = false;
                $this->state['sample_floor'] = time();
                foreach ($this->state['targets'] as &$target) { $target['samples'] = []; } unset($target);
                $reply = 'حالت واقعی فعال شد. ' . ($this->state['paused'] ? 'در تنظیمات DNS دکمهٔ «ادامهٔ تعویض» را بزنید.' : 'شمارش از تست بعدی شروع می‌شود.'); break;
            case '/retry':
                $domain = strtolower($parts[0] ?? '');
                if (!in_array($domain, $this->config['domains'], true) || empty($this->state['targets'][$domain]['pending'])) { $reply = 'عملیات معلقی برای این دامنه وجود ندارد.'; break; }
                $this->state['targets'][$domain]['pending']['attempts'] = 0;
                $reply = 'در کرون بعدی همان IP رزروشده دوباره بررسی می‌شود.'; break;
            case '/status':
                $policy = $this->config['operator_policy'] === 'all' ? 'هر دو نود' : 'یکی از دو نود';
                $reply = ($this->state['paused'] ? '⏸ تعویض متوقف' : '▶️ تعویض فعال') . ' | ' . ($this->state['dry_run'] ? 'شبیه‌سازی' : 'واقعی') . "\nآستانهٔ خرابی: {$this->state['threshold']} نتیجهٔ قرمز متوالی روی {$policy}";
                $lastRun = $this->state['last_run']
                    ? (new DateTimeImmutable('@' . $this->state['last_run']))->setTimezone(new DateTimeZone('Asia/Tehran'))->format('Y-m-d H:i:s') . ' (تهران)'
                    : 'دریافت موفق ثبت نشده';
                $reply .= "\nآخرین دریافت موفق: " . $lastRun;
                foreach ($this->config['domains'] as $domain) {
                    $this->target($domain); $t = $this->state['targets'][$domain];
                    $reply .= "\n\n{$domain}: " . ($t['current_ip'] ?? 'نامشخص') . (!empty($t['pending'])
                        ? ($t['pending']['attempts'] === 0 ? ' [در انتظار تست نهایی/تغییر]' : ' [پاسخ DNS در انتظار تطبیق]') : '');
                    if (!empty($t['rotation_note'])) { $reply .= "\nℹ️ " . $t['rotation_note']; }
                    $wait = max(0, ($t['not_before'] ?? 0) - time());
                    if ($wait > 0) { $reply .= "\n⏳ مهلت DNS: {$wait} ثانیه تا امکان تعویض"; }
                    foreach ($this->config['workers'] as $worker) {
                        $s = $t['samples'][$worker] ?? [];
                        $age = isset($s['ts']) ? max(0, time() - $s['ts']) : null;
                        $status = $s['status'] ?? '';
                        $fresh = $age !== null && $age <= $this->config['max_sample_age'];
                        $red = $fresh && in_array($status, $this->config['red_statuses'], true);
                        $indicator = match (true) {
                            $red => '🔴 قطع اتصال',
                            $fresh && $status === 'ok' => '🟢 وصل',
                            $fresh && $status === 'weak' => '⚪ کند',
                            default => '⚪ بدون نتیجهٔ تازه',
                        };
                        $reply .= "\n{$indicator} · " . strtoupper($worker)
                            . ($red ? ' · ' . ($s['count'] ?? 0) . ' قرمز متوالی' : '')
                            . ($age !== null ? " · {$age} ثانیه قبل" : '');
                    }
                } break;
            default: $reply = 'از منوی اصلی یک گزینه را انتخاب کنید.';
        }
        return $reply;
    }
    public static function publicIPv4(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) { return false; }
        // PHP's NO_RES_RANGE alone still permits multicast, CGNAT and documentation ranges.
        $number = ip2long($ip);
        foreach ([['100.64.0.0', 10], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
            ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as [$network, $bits]) {
            $mask = (0xffffffff << (32 - $bits)) & 0xffffffff;
            if (($number & $mask) === (ip2long($network) & $mask)) { return false; }
        }
        return true;
    }
    private function dns(string $domain): array
    {
        $records = $this->api->records($domain);
        $a = array_values(array_filter($records, fn($r) => ($r['type'] ?? '') === 'A' && strtolower($r['name'] ?? '') === $domain));
        $other = array_filter($records, fn($r) => in_array($r['type'] ?? '', ['AAAA', 'CNAME'], true));
        if (count($a) !== 1 || $other || !self::publicIPv4($a[0]['content'] ?? '') || empty($a[0]['id'])) {
            throw new RuntimeException('Exactly one A record and no AAAA/CNAME is required: ' . $domain);
        }
        return $a[0];
    }
    private function finish(string $domain, array $record, int $now): void
    {
        $t =& $this->state['targets'][$domain]; $p = $t['pending'];
        $this->state['pool'][$p['new']]['status'] = 'used';
        $this->state['pool'][$p['new']]['domain'] = $domain;
        $this->state['pool'][$p['old']] = ['status' => 'retired', 'domain' => $domain, 'retired_at' => $now];
        $t['current_ip'] = $p['new']; $t['changed_at'] = $now;
        $ttl = (int)($record['ttl'] ?? 1); if ($ttl <= 1) { $ttl = 300; }
        $t['not_before'] = $now + max($this->config['cooldown_seconds'], $ttl + $this->config['dns_grace_seconds']);
        unset($t['manual_sample_after']);
        $t['samples'] = []; $t['pending'] = null; $t['awaiting_health'] = true;
        $t['last_live_verification'] = $p['proof'] ?? null;
        $this->queue("🔄 تغییر DNS تأیید شد\n{$domain}\n{$p['old']} → {$p['new']}\nعلت: {$p['reason']}\nدر انتظار تست تازه پس از مهلت DNS.");
        $this->save();
    }

    private function observeManualDnsChange(string $domain, array $record, int $now): void
    {
        $target = &$this->state['targets'][$domain];
        // Cloudflare's record timestamp gives a more precise boundary than the next cron run.
        $changed = $now;
        $modifiedOn = (string)($record['modified_on'] ?? '');
        if (preg_match('/^\d{4}-\d{2}-\d{2}T.*Z$/D', $modifiedOn)) {
            $parsed = strtotime($modifiedOn);
            if ($parsed !== false && $parsed > 0 && $parsed <= $now) { $changed = $parsed; }
        }
        $ttl = (int)($record['ttl'] ?? 1);
        if ($ttl <= 1) { $ttl = 300; }
        $target['samples'] = [];
        $target['awaiting_health'] = false;
        // A manual edit gets its DNS cache window, not the cooldown for repeated bot rotations.
        $target['not_before'] = $changed + $ttl + $this->config['dns_grace_seconds'];
        if (empty($record['proxied'])) {
            $target['manual_sample_after'] = $changed;
        } else {
            // Proxied addresses do not reveal origin changes to the monitor.
            unset($target['manual_sample_after']);
        }
        $this->alert('external-' . $domain, "ℹ️ تغییر دستی DNS برای {$domain} ثبت شد. نمونه‌های قبلی پاک شدند و تعویض پس از مهلت DNS قابل انجام است.");
    }
    private function reconcile(string $domain, array $record, int $now, bool $allowMutation = true): void
    {
        $t =& $this->state['targets'][$domain]; $p = $t['pending'];
        if ($record['content'] === $p['new']) { $this->finish($domain, $record, $now); return; }
        if ($record['id'] !== $p['record_id'] || $record['content'] !== $p['old']) {
            $this->alert('conflict-' . $domain, "⛔ DNS دامنه {$domain} خارج از ربات تغییر کرده؛ IP رزروشده نگه داشته شد. بررسی دستی لازم است."); return;
        }
        if (!$allowMutation) { return; }
        if ($p['attempts'] >= 3 || $this->state['paused'] || $this->state['dry_run']) {
            $this->alert('pending-' . $domain, "⚠️ تأیید تغییر DNS برای {$domain} معلق است. IP رزرو باقی مانده و گزینهٔ تلاش دوباره در «تعویض DNS» در دسترس است."); return;
        }
        if (($this->config['require_live_preflight'] ?? true) && !$this->proofFresh($domain, $now)) { return; }
        if ($p['attempts'] === 0 && ($p['proof']['download_group'] ?? '') === 'fallback'
            && $this->poolCandidate(completeOnly: true) !== null) {
            $this->state['pool'][$p['new']]['status'] = 'available';
            $t['pending'] = null;
            $this->save();
            return;
        }
        $t['pending']['attempts']++; $this->save();
        try {
            $this->api->patch($p['record_id'], $p['new']);
            $verify = $this->dns($domain);
            if ($verify['content'] === $p['new']) { $this->finish($domain, $verify, $now); }
        } catch (Throwable $e) {
            $this->alert('patch-' . $domain, "⚠️ پاسخ تغییر DNS برای {$domain} قطعی نیست؛ اجرای بعدی ابتدا وضعیت Cloudflare را تطبیق می‌دهد.");
        }
    }
    public function tick(?int $clock = null): void
    {
        $now = $clock ?? time();
        // Reconcile pending DNS actions even if monitoring becomes unavailable.
        $dns = [];
        foreach ($this->config['domains'] as $domain) {
            $this->target($domain);
            unset($this->state['targets'][$domain]['rotation_note']);
            try {
                $dns[$domain] = $this->dns($domain);
                $old = $this->state['targets'][$domain]['current_ip'];
                if ($old !== null && $old !== $dns[$domain]['content'] && empty($this->state['targets'][$domain]['pending'])) {
                    $this->observeManualDnsChange($domain, $dns[$domain], $now);
                }
                $this->state['targets'][$domain]['current_ip'] = $dns[$domain]['content'];
            } catch (Throwable $e) { $this->alert('dns-' . $domain, "⛔ خواندن رکورد DNS ممکن نشد یا رکورد مبهم است: {$domain}. تعویض متوقف می‌ماند."); }
        }
        // Never reuse any IP found on either managed domain, even if manually added to pool.
        foreach ($dns as $domain => $r) {
            $ip = $r['content'];
            if (($this->state['pool'][$ip]['status'] ?? '') === 'available') {
                $this->state['pool'][$ip] = ['status' => 'used', 'domain' => $domain];
            }
        }
        $simulated = [];
        foreach ($this->config['domains'] as $domain) {
            if (!empty($this->state['targets'][$domain]['pending']) && isset($dns[$domain])) {
                $this->reconcile($domain, $dns[$domain], $now, false);
                // Refresh snapshot after reconciliation, before selecting another IP.
                $dns[$domain]['content'] = $this->state['targets'][$domain]['current_ip'];
            }
        }
        try { $data = $this->api->monitor(); }
        catch (Throwable $e) {
            foreach ($this->state['targets'] as &$target) { $target['samples'] = []; } unset($target);
            $cause = $this->connectionFailure('status', $e);
            $this->alert('monitor', "⚠️ دریافت وضعیت مانیتورینگ ناموفق بود.\n{$cause}\nاز «اتصال API» مسیر شبکه را بررسی کنید.");
            $this->poolWarning(); $this->save(); return;
        }
        $schema = $this->statusIssue($data, $now);
        if ($schema !== null) {
            $this->recordConnection('status', $schema, false);
            foreach ($this->state['targets'] as &$target) { $target['samples'] = []; } unset($target);
            $this->alert('schema', '⚠️ پاسخ مانیتورینگ قدیمی یا نامعتبر است؛ تعویض متوقف شد.');
            $this->poolWarning(); $this->save(); return;
        }
        $this->recordConnection('status', 'پاسخ معتبر دریافت شد.', true);
        $sources = array_column($data['sources'], null, 'id');
        $workers = array_column($data['workers'], null, 'id');
        foreach ($this->config['domains'] as $domain) {
            $this->target($domain); $t =& $this->state['targets'][$domain];
            $matches = array_values(array_filter($data['configs'], fn($c) => ($c['enabled'] ?? false) === true
                && strtolower($c['address'] ?? '') === $domain
                && ($sources[$c['source_id'] ?? '']['name'] ?? '') === $this->config['source_name']
                && ($sources[$c['source_id'] ?? '']['enabled'] ?? false) === true));
            if (count($matches) !== 1) {
                $this->cancelUnsent($domain);
                $t['rotation_note'] = 'برای این دامنه دقیقاً یک کانفیگ فعال پیدا نشد.';
                $t['samples'] = []; $this->alert('config-' . $domain, "⚠️ برای {$domain} دقیقاً یک کانفیگ فعال پیدا نشد؛ تعویض متوقف شد."); continue;
            }
            $c = $matches[0]; $key = $c['source_id'] . ':' . $c['id'];
            if (($t['config_key'] ?? '') !== $key) { $t['samples'] = []; $t['config_key'] = $key; }
            $dnsMatches = isset($dns[$domain]) && (!empty($dns[$domain]['proxied']) || ($c['entry_ip'] ?? '') === $dns[$domain]['content']);
            $sampleAfter = max($this->state['sample_floor'] ?? 0, $t['manual_sample_after'] ?? $t['not_before'] ?? 0);
            $trigger = []; $healthy = 0;
            foreach ($this->config['workers'] as $worker) {
                $sample = $data['latest'][$key][$worker] ?? [];
                $w = $workers[$worker] ?? [];
                $ts = (int)($sample['ts'] ?? 0); $status = (string)($sample['status'] ?? 'missing');
                $previous = $t['samples'][$worker] ?? [];
                if ($ts <= ($this->state['sample_floor'] ?? 0)) {
                    $t['samples'][$worker] = ['ts' => max($ts, (int)($previous['ts'] ?? 0)), 'count' => 0, 'status' => 'awaiting-new-test']; continue;
                }
                $valid = ($w['online'] ?? false) === true && $now - (int)($w['last_seen'] ?? 0) <= $this->config['max_sample_age']
                    && $ts <= $now + 30 && $now - $ts <= $this->config['max_sample_age'];
                if (!$valid) {
                    $t['samples'][$worker] = ['ts' => max($ts, (int)($previous['ts'] ?? 0)), 'count' => 0, 'status' => 'stale/offline'];
                    $this->alert('stale-' . $domain . '-' . $worker, "⚠️ تست تازه در دسترس نیست: {$domain} / {$worker}. این وضعیت قرمز شمرده نمی‌شود."); continue;
                }
                if ($ts < (int)($previous['ts'] ?? 0)) {
                    $t['samples'][$worker]['count'] = 0; continue;
                }
                if ($ts === (int)($previous['ts'] ?? 0) && $status !== ($previous['status'] ?? '')) {
                    // A corrected result for the same test is not another independent failure.
                    $t['samples'][$worker] = ['ts' => $ts, 'count' => 0, 'status' => $status];
                }
                if ($ts > (int)($previous['ts'] ?? 0)) {
                    $red = in_array($status, $this->config['red_statuses'], true);
                    $continuous = isset($previous['ts']) && $ts - $previous['ts'] <= $this->config['max_sample_gap'];
                    $count = $red ? ($continuous ? (int)($previous['count'] ?? 0) : 0) + 1 : 0;
                    $t['samples'][$worker] = ['ts' => $ts, 'count' => $count, 'status' => $status];
                }
                if (!$dnsMatches || $ts <= $sampleAfter) {
                    $t['samples'][$worker]['count'] = 0;
                }
                $s = $t['samples'][$worker] ?? [];
                if (in_array($s['status'] ?? '', $this->config['red_statuses'], true) && ($s['count'] ?? 0) >= $this->state['threshold']) { $trigger[] = $worker; }
                if (($s['status'] ?? '') === 'ok' && $ts > ($t['not_before'] ?? 0)) { $healthy++; }
            }
            if (!isset($dns[$domain])) {
                $t['rotation_note'] = 'رکورد فعلی Cloudflare خوانده نشد.';
                if (!empty($t['pending'])) { $t['pending']['eligible_until'] = 0; }
                continue;
            }
            if (!$dnsMatches) {
                $t['rotation_note'] = 'در انتظار تطبیق IP مانیتورینگ با DNS فعلی.';
                if (!empty($t['pending'])) { $t['pending']['eligible_until'] = 0; }
                $this->alert('resolve-' . $domain, "⚠️ IP ثبت‌شده در مانیتورینگ با DNS فعلی {$domain} متفاوت است. شمارش تا تطبیق متوقف است.");
                continue;
            }
            if (!empty($t['awaiting_health']) && $healthy === count($this->config['workers'])) {
                $t['awaiting_health'] = false;
                $this->queue("✅ اتصال {$domain} پس از تغییر IP روی MCI-THR و MKH-THR تأیید شد.");
            }
            $shouldRotate = $this->config['operator_policy'] === 'all' ? count($trigger) === count($this->config['workers']) : count($trigger) > 0;
            if (!$shouldRotate) {
                $t['rotation_note'] = 'در انتظار تعداد لازم از تست‌های تازه و مستقل.';
                $this->cancelUnsent($domain);
                continue;
            }
            if ($this->state['paused']) { $t['rotation_note'] = 'تعویض دستی متوقف شده است.'; continue; }
            if ($now < $t['not_before']) {
                $t['rotation_note'] = 'آستانهٔ خرابی رسیده است. تعویض پس از مهلت DNS بررسی می‌شود.';
                continue;
            }
            if (count($dns) !== count($this->config['domains'])) { continue; }
            if (!empty($t['pending'])) {
                $t['pending']['eligible_until'] = $now + 60;
                $this->reconcile($domain, $dns[$domain], $now);
                $dns[$domain]['content'] = $t['current_ip'];
                continue;
            }
            if (!$this->state['dry_run'] && $now < $this->state['live']['blocked_until']
                && !($this->state['live']['scan_quota_wait'] ?? false)) {
                $t['rotation_note'] = 'در انتظار در دسترس شدن تست لایو یا سهمیهٔ API.';
                continue;
            }
            $candidate = $this->poolCandidate(array_merge(array_column($dns, 'content'), $simulated));
            if ($candidate === null) {
                $t['rotation_note'] = 'IP جایگزین در مخزن آماده نیست.';
                $this->alert('no-ip', "⛔ IP آماده و متفاوت برای {$domain} موجود نیست. از «مخزن IP» یا «اسکن» استفاده کنید.");
                continue;
            }
            $reason = implode(', ', $trigger) . ' / ' . $this->state['threshold'] . ' قرمز متوالی';
            if ($this->state['dry_run']) {
                $simulated[] = $candidate;
                $this->alert('dry-' . $domain, "🧪 شبیه‌سازی: {$domain} باید از {$dns[$domain]['content']} به {$candidate} تغییر کند. علت: {$reason}"); continue;
            }
            $this->state['pool'][$candidate]['status'] = 'reserved';
            $t['pending'] = ['old' => $dns[$domain]['content'], 'new' => $candidate, 'record_id' => $dns[$domain]['id'],
                'created_at' => $now, 'attempts' => 0, 'reason' => $reason, 'eligible_until' => $now + 60];
            // Journal reservation BEFORE sending PATCH. Crash/timeout cannot allocate it twice.
            $this->save();
            $this->reconcile($domain, $dns[$domain], $now);
            $dns[$domain]['content'] = $t['current_ip'];
        }
        unset($t);
        $this->state['last_run'] = $now;
        $this->poolWarning();
        $this->save();
    }
}
