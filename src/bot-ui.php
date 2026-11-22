<?php
declare(strict_types=1);

trait BotUi
{
    private function keyboard(array $rows): array
    {
        return ['inline_keyboard' => array_map(
            fn($row) => array_map(fn($button) => ['text' => $button[0], 'callback_data' => $button[1]], $row),
            $rows
        )];
    }

    private function deliver(string|array $entry): void
    {
        $data = is_string($entry) ? ['text' => $entry, 'reply_markup' => $this->keyboard([
            [['🏠 منوی اصلی', 'home'], ['🔌 اتصال API', 'connection']],
            [['📦 مخزن IP', 'pool'], ['🔎 اسکن', 'scan']],
        ])] : $entry;
        $data['chat_id'] = $this->config['telegram_chat_id'];
        if (isset($data['message_id'])) {
            try {
                $this->api->telegram('editMessageText', $data);
                return;
            } catch (HttpFailure $e) {
                if ($e->status !== 400) { throw $e; }
                unset($data['message_id']);
            }
        }
        $this->api->telegram('sendMessage', $data);
    }

    private function screen(string $text, array $rows, array $previous = []): void
    {
        $markup = $this->keyboard($rows);
        if (($previous['text'] ?? null) === $text && ($previous['reply_markup'] ?? null) === $markup) { return; }
        if (count($this->state['outbox']) >= 150) { array_shift($this->state['outbox']); }
        $data = ['text' => $text, 'reply_markup' => $markup];
        if (!empty($previous['message_id'])) { $data['message_id'] = (int)$previous['message_id']; }
        array_unshift($this->state['outbox'], $data);
    }

    private function handleUpdate(array $update): void
    {
        $callback = $update['callback_query'] ?? null;
        $message = $callback['message'] ?? $update['message'] ?? [];
        $from = $callback['from'] ?? $message['from'] ?? [];
        if (($message['chat']['type'] ?? '') !== 'private'
            || (string)($message['chat']['id'] ?? '') !== (string)$this->config['telegram_chat_id']
            || !in_array((string)($from['id'] ?? ''), array_map('strval', $this->config['admin_user_ids']), true)) { return; }
        $id = (string)($update['update_id'] ?? '');
        if ($id === '' || isset($this->state['updates'][$id])) { return; }
        if ($callback) {
            if (empty($callback['id'])) { return; }
            try { $this->api->telegram('answerCallbackQuery', ['callback_query_id' => $callback['id']]); }
            catch (Throwable $e) { /* The menu can still be updated after the callback expires. */ }
            $this->menuAction((string)($callback['data'] ?? ''), $message);
        } elseif (is_string($message['text'] ?? null)) {
            $this->menuText(trim($message['text']));
        } else { return; }
        $this->state['updates'][$id] = time();
        if (count($this->state['updates']) > 500) {
            $this->state['updates'] = array_slice($this->state['updates'], -500, null, true);
        }
        $this->save();
    }

    private function menuText(string $text): void
    {
        $parts = preg_split('/\s+/', $text);
        $cmd = strtolower(explode('@', array_shift($parts))[0]);
        $routes = [
            '/start' => 'home', '/help' => 'help', '/status' => 'status', '/pool' => 'pool', '/scanstatus' => 'scan',
            'وضعیت' => 'status', 'مخزن' => 'pool', 'وضعیت اسکن' => 'scan', 'راهنما' => 'help',
        ];
        if ($text === 'مخزن IP') { $cmd = 'مخزن'; }
        if ($text === 'وضعیت اسکن') { $cmd = 'وضعیت اسکن'; }
        if (isset($routes[$cmd])) {
            $this->menuAction($routes[$cmd], []);
            if ($cmd === '/start' && empty($this->state['ui']['old_keyboard_removed'])) {
                array_unshift($this->state['outbox'], ['text' => 'منوی ربات زیر پیام نمایش داده می‌شود.', 'reply_markup' => ['remove_keyboard' => true]]);
                $this->state['ui']['old_keyboard_removed'] = true;
            }
            return;
        }
        $input = $this->state['ui']['input'] ?? [];
        if (!str_starts_with($cmd, '/') && ($input['expires'] ?? 0) >= time()) {
            $this->handleMenuInput($input, $text);
            return;
        }
        unset($this->state['ui']['input']);
        if ($cmd === '/add') {
            $this->addPoolIPs($parts);
            return;
        }
        $legacy = ['/scan' => 'scan', '/scanstop' => 'scan', '/scanresume' => 'scan',
            '/remove' => 'pool', '/threshold' => 'dns', '/pause' => 'dns', '/resume' => 'dns',
            '/dryrun' => 'dns', '/live' => 'dns', '/retry' => 'dns'];
        if (isset($legacy[$cmd])) {
            $this->showMenu($legacy[$cmd], [], $this->executeCommand($cmd, $parts));
            return;
        }
        $this->showMenu('home');
    }

    private function menuAction(string $action, array $message): void
    {
        $prompts = [
            'input-scan' => ['scan', "یک IPv4 یا رنج بفرستید.\nنمونهٔ رنج: 104.16.0.0/24\nنمونهٔ بازه: 104.16.0.10-104.16.0.20"],
            'input-add' => ['pool', 'آدرس‌های IPv4 عمومی را با فاصله یا سطر جدید بفرستید.'],
            'input-proxy' => ['connection', "آدرس SOCKS5 مورد اعتماد را با پورت بفرستید.\nقالب: socks5h://proxy.example.com:1080\nبرای پروکسی دارای رمز، از فایل خصوصی config.php استفاده کنید."],
        ];
        unset($this->state['ui']['input']);
        if (preg_match('/^pool-(confirm|cancel):([a-f0-9]{16})$/D', $action, $match)) {
            $this->confirmPoolIPs($match[1] === 'confirm', $match[2], $message);
            return;
        }
        unset($this->state['ui']['pool_confirmation']);
        if (isset($prompts[$action])) {
            [$back, $text] = $prompts[$action];
            $this->state['ui']['input'] = ['action' => $action, 'back' => $back, 'expires' => time() + 600];
            $this->screen($text, [[['↩️ انصراف', $back]]], $message);
            return;
        }
        $commands = [
            'scan-stop' => ['scan', '/scanstop', []], 'scan-resume' => ['scan', '/scanresume', []],
            'dns-pause' => ['dns', '/pause', []], 'dns-resume' => ['dns', '/resume', []],
            'dns-dry' => ['dns', '/dryrun', []], 'dns-confirm-live' => ['dns', '/live', []],
            'threshold-2' => ['dns', '/threshold', ['2']], 'threshold-3' => ['dns', '/threshold', ['3']],
        ];
        if (isset($commands[$action])) {
            [$page, $cmd, $args] = $commands[$action];
            $this->showMenu($page, $message, $this->executeCommand($cmd, $args));
            return;
        }
        if ($action === 'dns-live') {
            $this->screen('در حالت واقعی، ربات پس از خرابی تأییدشده و تست سبز IP جایگزین، رکورد DNS را تغییر می‌دهد. حالت واقعی فعال شود؟',
                [[['فعال‌کردن حالت واقعی', 'dns-confirm-live']], [['↩️ انصراف', 'dns']]], $message);
            return;
        }
        if (preg_match('/^retry-([01])$/D', $action, $match)) {
            $this->showMenu('dns', $message, $this->executeCommand('/retry', [$this->config['domains'][(int)$match[1]]]));
            return;
        }
        if (preg_match('/^remove-(pick|confirm):([0-9.]+)$/D', $action, $match) && self::publicIPv4($match[2])) {
            if ($match[1] === 'pick') {
                $this->screen("آدرس {$match[2]} از مخزن آماده حذف شود؟", [
                    [['حذف IP', 'remove-confirm:' . $match[2]]], [['↩️ انصراف', 'pool']],
                ], $message);
            } else {
                $this->showMenu('pool', $message, $this->executeCommand('/remove', [$match[2]]));
            }
            return;
        }
        if ($action === 'probe-direct' || $action === 'probe-current') {
            $proxy = $action === 'probe-direct' ? null : $this->selectedProxy();
            [$report] = $this->probeConnection($proxy);
            $this->showMenu('connection', $message, $report);
            return;
        }
        if ($action === 'proxy-direct' || $action === 'proxy-config') {
            $proxy = $action === 'proxy-config' ? $this->configProxy() : null;
            if ($action === 'proxy-config' && $proxy === null) {
                $this->showMenu('connection', $message, 'آدرس معتبر SOCKS5 در config.php وارد نشده است.');
            } else {
                $this->chooseProxy($action === 'proxy-config' ? 'config' : 'direct', $proxy, $message);
            }
            return;
        }
        $this->showMenu($action, $message);
    }

    private function handleMenuInput(array $input, string $text): void
    {
        if ($input['action'] === 'input-proxy') {
            $proxy = self::normalizeProxy($text);
            if ($proxy === null) {
                $this->showMenu('connection', [], 'آدرس معتبر SOCKS5 همراه پورت وارد کنید. رمز پروکسی را در تلگرام نفرستید.');
                return;
            }
            $this->chooseProxy($proxy, $proxy, []);
            return;
        }
        $parts = preg_split('/[\s,،]+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        unset($this->state['ui']['input']);
        if ($input['action'] === 'input-add') {
            $this->addPoolIPs($parts);
            return;
        }
        $reply = $this->executeCommand('/scan', $parts);
        $this->showMenu($input['back'], [], $reply);
    }

    private function showMenu(string $page, array $message = [], string $notice = ''): void
    {
        $home = [['🏠 منوی اصلی', 'home']];
        $rows = [$home];
        switch ($page) {
            case 'status':
                $text = "📊 وضعیت دامنه‌ها\n🟢 وصل   🔴 قطع   ⚪ کند یا بدون تست تازه\n\n" . $this->executeCommand('/status', []);
                array_unshift($rows, [['🔄 تازه‌سازی', 'status'], ['🔌 اتصال API', 'connection']]);
                break;
            case 'scan':
                $text = "🔎 اسکن IP\n\n" . $this->scanStatus();
                array_unshift($rows, [['➕ افزودن رنج', 'input-scan']], [
                    $this->state['scan']['paused'] ? ['▶️ ادامهٔ اسکن', 'scan-resume'] : ['⏸ توقف اسکن', 'scan-stop'],
                    ['🔄 تازه‌سازی', 'scan'],
                ], [['🔌 اتصال API', 'connection']]);
                break;
            case 'pool':
                $text = "📦 مخزن IP\n\n" . $this->executeCommand('/pool', []);
                array_unshift($rows, [['➕ افزودن IP', 'input-add'], ['➖ حذف IP', 'remove']]);
                break;
            case 'dns':
                $mode = $this->state['dry_run'] ? '🧪 شبیه‌سازی' : '⚡ واقعی';
                $running = $this->state['paused'] ? 'متوقف' : 'فعال';
                $threshold = $this->state['threshold'];
                $text = "⚙️ تنظیمات تعویض DNS\n\n{$mode} · تعویض {$running}\n"
                    . "آستانه: {$threshold} تست مستقل قرمزِ متوالی\n\n"
                    . "🧪 شبیه‌سازی: خرابی و IP پیشنهادی را گزارش می‌دهد. رکورد Cloudflare و موجودی مخزن تغییر نمی‌کنند.\n"
                    . "⚡ واقعی: پس از خرابی تأییدشده، IP جایگزین را روی چهار نود تست می‌کند و با نتیجهٔ سبز DNS را تغییر می‌دهد.\n"
                    . "⏸ توقف تعویض: پایش و اسکن ادامه دارند. برای تعویض دوباره «ادامهٔ تعویض» را بزنید.";
                array_unshift($rows, [
                    $this->state['dry_run'] ? ['⚡ انتخاب حالت واقعی', 'dns-live'] : ['🧪 انتخاب شبیه‌سازی', 'dns-dry'],
                ], [
                    $this->state['paused'] ? ['▶️ ادامهٔ تعویض', 'dns-resume'] : ['⏸ توقف تعویض', 'dns-pause'],
                ], [
                    [($threshold === 2 ? '✓ ' : '') . 'آستانهٔ ۲ قرمز', 'threshold-2'],
                    [($threshold === 3 ? '✓ ' : '') . 'آستانهٔ ۳ قرمز', 'threshold-3'],
                ]);
                foreach ($this->config['domains'] as $index => $domain) {
                    if (!empty($this->state['targets'][$domain]['pending'])) {
                        array_unshift($rows, [['تلاش دوبارهٔ ' . $domain, 'retry-' . $index]]);
                    }
                }
                break;
            case 'remove':
                $available = array_keys(array_filter($this->state['pool'], fn($p) => $p['status'] === 'available'));
                $text = $available ? 'آدرس موردنظر را برای حذف انتخاب کنید.' : 'مخزن IP آماده‌ای برای حذف ندارد.';
                $rows = $this->removeRows($available, 0);
                break;
            case 'connection':
                $text = $this->connectionScreen();
                array_unshift($rows, [['🧪 آزمون مسیر فعلی', 'probe-current'], ['آزمون مستقیم', 'probe-direct']],
                    [['➕ تنظیم SOCKS5', 'input-proxy'], ['اتصال مستقیم', 'proxy-direct']]);
                if ($this->configProxy() !== null) { array_unshift($rows, [['استفاده از پروکسی فایل تنظیمات', 'proxy-config']]); }
                break;
            case 'help':
                $text = "راهنمای ربات\n\n۱. در «اتصال API» از داخل هاست مسیر شبکه را آزمایش کنید.\n"
                    . "۲. در «اسکن IP» رنج را وارد کنید. هر IP روی چهار نود تست می‌شود و نتیجهٔ سبز وارد مخزن می‌شود.\n"
                    . "۳. در «مخزن IP» می‌توانید فهرست را ببینید یا دستی IP اضافه و حذف کنید.\n"
                    . "۴. پایش دوره‌ای خرابی را روی MCI و MKH بررسی می‌کند. پس از رسیدن به آستانه، IP جایگزین یک بار دیگر روی چهار نود تست می‌شود. کرون سی‌پنل، پایش و اسکن را اجرا می‌کند.\n"
                    . "۵. در «تعویض DNS» حالت شبیه‌سازی نتیجه را گزارش می‌کند. حالت واقعی می‌تواند رکورد دامنه را تغییر دهد. توقف اسکن و توقف تعویض مستقل‌اند.";
                array_unshift($rows, [['🔌 اتصال API', 'connection'], ['🔎 اسکن IP', 'scan']], [['⚙️ تعویض DNS', 'dns']]);
                break;
            default:
                if (preg_match('/^remove-page:(\d{1,5})$/D', $page, $match)) {
                    $available = array_keys(array_filter($this->state['pool'], fn($p) => $p['status'] === 'available'));
                    $this->screen('آدرس موردنظر را برای حذف انتخاب کنید.', $this->removeRows($available, (int)$match[1]), $message);
                    return;
                }
                $text = "🛰 کنترل مانیتورینگ\n\nIP آماده در مخزن: " . $this->readyCount()
                    . "\n" . ($this->state['scan']['paused'] ? 'اسکن متوقف است.'
                        : ($this->scanRemaining() ? 'اسکن فعال است.' : 'صف اسکن خالی است.'))
                    . "\n" . ($this->state['dry_run'] ? 'DNS در حالت شبیه‌سازی است.' : 'DNS در حالت واقعی است.')
                    . ($this->state['paused'] ? ' تعویض متوقف است.' : '');
                $rows = [
                    [['📊 وضعیت دامنه‌ها', 'status'], ['🔌 اتصال API', 'connection']],
                    [['🔎 اسکن IP', 'scan'], ['📦 مخزن IP', 'pool']],
                    [['⚙️ تعویض DNS', 'dns'], ['❔ راهنمای کار', 'help']],
                ];
        }
        $this->screen($notice === '' ? $text : $notice . "\n\n" . $text, $rows, $message);
    }

    private function removeRows(array $available, int $page): array
    {
        $page = min($page, max(0, (int)ceil(count($available) / 10) - 1));
        $rows = array_chunk(array_map(fn($ip) => [$ip, 'remove-pick:' . $ip], array_slice($available, $page * 10, 10)), 2);
        $nav = [];
        if ($page > 0) { $nav[] = ['قبلی', 'remove-page:' . ($page - 1)]; }
        if (($page + 1) * 10 < count($available)) { $nav[] = ['بعدی', 'remove-page:' . ($page + 1)]; }
        if ($nav) { $rows[] = $nav; }
        $rows[] = [['↩️ مخزن IP', 'pool']];
        return $rows;
    }

    private function poolIPProtected(string $ip): bool
    {
        $entry = $this->state['pool'][$ip] ?? [];
        if (in_array($entry['status'] ?? '', ['reserved', 'testing'], true) || ($this->state['live']['active']['ip'] ?? '') === $ip) { return true; }
        foreach ($this->state['targets'] as $target) {
            if (in_array($ip, [$target['current_ip'] ?? null, $target['pending']['old'] ?? null, $target['pending']['new'] ?? null], true)) { return true; }
        }
        return false;
    }

    private function addPoolIPs(array $parts): void
    {
        unset($this->state['ui']['pool_confirmation']);
        $ips = array_values(array_unique($parts));
        if (!$ips || count($ips) > 100 || array_filter($ips, fn($ip) => !self::publicIPv4($ip))) {
            $this->showMenu('pool', [], 'حداکثر ۱۰۰ آدرس IPv4 عمومی را با فاصله یا سطر جدید بفرستید.');
            return;
        }
        $duplicates = [];
        $added = 0;
        $protected = 0;
        foreach ($ips as $ip) {
            if ($this->poolIPProtected($ip)) { $protected++; continue; }
            if (isset($this->state['pool'][$ip])) { $duplicates[] = $ip; continue; }
            $this->state['pool'][$ip] = ['status' => 'available', 'added_at' => time()];
            $added++;
        }
        $summary = "{$added} IP جدید اضافه شد." . ($protected ? "\n{$protected} IP در حال استفاده، تست یا رزرو بود." : '');
        if (!$duplicates) { $this->showMenu('pool', [], $summary); return; }
        $token = bin2hex(random_bytes(8));
        $this->state['ui']['pool_confirmation'] = ['token' => $token, 'ips' => $duplicates, 'expires' => time() + 600];
        $list = implode("\n", array_slice($duplicates, 0, 20));
        if (count($duplicates) > 20) { $list .= "\n… و " . (count($duplicates) - 20) . ' مورد دیگر'; }
        $this->screen($summary . "\n\n" . count($duplicates) . " IP قبلاً ثبت شده‌اند. با تأیید، IPهای قابل‌استفاده دوباره آماده می‌شوند و هر آدرس فقط یک بار در مخزن می‌ماند.\n\n" . $list,
            [[['✅ تأیید افزودن دوباره', 'pool-confirm:' . $token]], [['انصراف', 'pool-cancel:' . $token]]]);
    }

    private function confirmPoolIPs(bool $confirm, string $token, array $message): void
    {
        $request = $this->state['ui']['pool_confirmation'] ?? [];
        if (($request['token'] ?? '') !== $token || ($request['expires'] ?? 0) <= time()) {
            $this->showMenu('pool', $message, 'این تأیید منقضی شده است. آدرس را دوباره بفرستید.');
            return;
        }
        unset($this->state['ui']['pool_confirmation']);
        if (!$confirm) { $this->showMenu('pool', $message, 'افزودن دوباره لغو شد.'); return; }
        $restored = 0;
        $already = 0;
        foreach ($request['ips'] as $ip) {
            if ($this->poolIPProtected($ip)) { continue; }
            if (($this->state['pool'][$ip]['status'] ?? '') === 'available') { $already++; continue; }
            $this->state['pool'][$ip] = ['status' => 'available', 'added_at' => time()];
            $restored++;
        }
        $skipped = count($request['ips']) - $restored - $already;
        $this->showMenu('pool', $message, "✅ {$restored} IP دوباره آماده شد. {$already} IP از قبل آماده بود."
            . ($skipped ? " {$skipped} IP به دلیل استفاده یا رزرو قابل بازگردانی نبود." : ''));
    }

    public static function normalizeProxy(string $value, bool $allowCredentials = false): ?string
    {
        if (strlen($value) > 512 || preg_match('/[\x00-\x20\x7f\\\\]/', $value)) { return null; }
        $parts = parse_url(str_contains($value, '://') ? $value : 'socks5h://' . $value);
        if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['socks5', 'socks5h'], true)
            || empty($parts['port']) || array_intersect(['path', 'query', 'fragment'], array_keys($parts))
            || (!$allowCredentials && (isset($parts['user']) || isset($parts['pass'])))) { return null; }
        $host = $parts['host'] ?? '';
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) === false
            && !preg_match('/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/iD', $host)) { return null; }
        $credentials = isset($parts['user']) ? $parts['user'] . (isset($parts['pass']) ? ':' . $parts['pass'] : '') . '@' : '';
        return 'socks5h://' . $credentials . $host . ':' . $parts['port'];
    }

    private function configProxy(): ?string
    {
        return self::normalizeProxy((string)($this->config['monitor_socks_proxy'] ?? ''), true);
    }

    private function selectedProxy(): ?string
    {
        $setting = $this->state['monitor_proxy'] ?? 'config';
        return match ($setting) {
            'direct' => null,
            'config' => $this->configProxy(),
            default => self::normalizeProxy($setting),
        };
    }

    private function applyProxy(): void
    {
        if ($this->api instanceof Network) { $this->api->setMonitorProxy($this->selectedProxy()); }
    }

    private function chooseProxy(string $setting, ?string $proxy, array $message): void
    {
        [$report, $passed] = $this->probeConnection($proxy);
        if ($passed || $setting === 'direct') {
            $this->state['monitor_proxy'] = $setting;
            $this->state['live']['blocked_until'] = 0;
            $this->applyProxy();
            $report .= "\nمسیر جدید برای API مانیتورینگ انتخاب شد.";
        } else {
            $report .= "\nپروکسی ذخیره نشد. هر دو API باید از مسیر جدید پاسخ معتبر بدهند.";
        }
        $this->showMenu('connection', $message, $report);
    }

    private function probeConnection(?string $proxy): array
    {
        // Use an independent budget and the same HTTP client as cron, without submitting live jobs.
        $api = $this->api;
        if ($api instanceof Network) {
            $api = new Network($this->config, 22);
            $api->setMonitorProxy($proxy);
        }
        $lines = [$proxy === null ? 'آزمون از هاست • مستقیم' : 'آزمون از هاست • SOCKS5'];
        $passed = true;
        foreach (['Status' => 'monitor', 'Live' => 'liveMeta'] as $name => $method) {
            try {
                $data = $api->$method();
                $issue = $name === 'Status' ? $this->statusIssue($data, time()) : $this->liveIssue($data);
                $lines[] = $name . ' • ' . ($issue ?? 'پاسخ معتبر');
                if ($name === 'Live' && $issue === null) {
                    $offline = $this->offlineWorkers($data);
                    if ($offline) { $lines[] = 'نودهای آماده‌نبودۀ Live: ' . implode(', ', $offline); }
                }
                $passed = $passed && $issue === null;
            } catch (Throwable $e) {
                $lines[] = $name . ' • ' . $this->safeFailure($e);
                $passed = false;
            }
        }
        return [implode("\n", $lines), $passed];
    }

    private function connectionScreen(): string
    {
        $url = parse_url($this->config['monitor_url']);
        $endpoint = ($url['host'] ?? 'نامشخص') . (isset($url['port']) ? ':' . $url['port'] : '');
        $text = "🔌 اتصال API مانیتورینگ\n\nمقصد {$endpoint}\nمسیر فعلی " . ($this->selectedProxy() === null ? 'مستقیم' : 'SOCKS5');
        foreach (['status' => 'Status', 'live' => 'Live'] as $key => $label) {
            $saved = $this->state['connection'][$key] ?? null;
            $text .= "\n{$label} • " . ($saved['detail'] ?? 'هنوز نتیجه‌ای ثبت نشده') .
                ($saved ? ' (' . max(0, time() - $saved['at']) . ' ثانیه قبل)' : '');
        }
        return $text;
    }

    private function safeFailure(Throwable $e): string
    {
        if ($e instanceof HttpFailure) {
            return match ($e->curlCode) {
                0 => "سرور پاسخ HTTP {$e->status} داد.",
                5 => 'نام پروکسی پیدا نشد (cURL 5).',
                6 => 'نام مقصد پیدا نشد (cURL 6).',
                7 => 'اتصال TCP برقرار نشد (cURL 7).',
                28 => 'مهلت اتصال یا دریافت پاسخ تمام شد (cURL 28).',
                35, 60 => "برقراری TLS ناموفق بود (cURL {$e->curlCode}).",
                97 => 'مذاکره با پروکسی SOCKS ناموفق بود (cURL 97).',
                default => "خطای شبکه (cURL {$e->curlCode}).",
            };
        }
        if ($e instanceof JsonException) { return 'پاسخ JSON معتبر نیست.'; }
        return match ($e->getMessage()) {
            'Network time budget exhausted.' => 'بودجهٔ درخواست شبکه در این اجرای ربات تمام شد.',
            'PHP cURL extension is required.' => 'افزونهٔ cURL روی PHP هاست فعال نیست.',
            default => 'پاسخ یا تنظیمات API قابل پردازش نیست.',
        };
    }

    private function statusIssue(array $data, int $now): ?string
    {
        foreach (['configs', 'workers', 'latest', 'sources'] as $key) {
            if (!is_array($data[$key] ?? null)) { return 'ساختار پاسخ Status معتبر نیست.'; }
        }
        if (!is_numeric($data['now'] ?? null)) { return 'زمان در پاسخ Status وجود ندارد.'; }
        if (abs($now - (int)$data['now']) > $this->config['max_sample_age']) {
            return 'زمان پاسخ Status با ساعت هاست اختلاف دارد.';
        }
        return null;
    }

    private function liveIssue(array $data): ?string
    {
        if (!is_array($data['workers'] ?? null) || !is_array($data['checks'] ?? null)
            || !is_numeric($data['limits']['per_hour'] ?? null) || (int)$data['limits']['per_hour'] < 1
            || !is_numeric($data['limits']['cooldown_s'] ?? null) || !is_numeric($data['used_last_hour'] ?? null)) {
            return 'ساختار پاسخ Live معتبر نیست.';
        }
        if (($data['limits']['max_rounds'] ?? 0) < 1 || array_diff($this->config['live_checks'], $data['checks'])) {
            return 'API لایو همهٔ تست‌های موردنیاز را پشتیبانی نمی‌کند.';
        }
        return null;
    }

    private function offlineWorkers(array $meta): array
    {
        $workers = array_column($meta['workers'], null, 'id');
        return array_values(array_filter($this->config['live_workers'], fn($id) => ($workers[$id]['online'] ?? false) !== true));
    }

    private function recordConnection(string $key, string $detail, bool $ok): void
    {
        $previous = $this->state['connection'][$key] ?? [];
        if (($previous['detail'] ?? '') !== $detail || ($previous['ok'] ?? null) !== $ok) {
            error_log("Monitor API {$key}: {$detail}");
            if ($ok) { unset($this->state['alerts'][$key === 'live' ? 'live-meta' : 'monitor']); }
        }
        $this->state['connection'][$key] = ['detail' => $detail, 'ok' => $ok, 'at' => time()];
    }

    private function connectionFailure(string $key, Throwable $e): string
    {
        $cause = $this->safeFailure($e);
        $this->recordConnection($key, $cause, false);
        return $cause;
    }
}
