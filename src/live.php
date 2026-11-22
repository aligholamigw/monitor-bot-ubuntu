<?php
declare(strict_types=1);

final class IPv4Range
{
    public static function parse(string $input, int $maximum): array
    {
        if (preg_match('~^([0-9.]+)/([0-9]{1,2})$~D', $input, $m)) {
            if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || (int)$m[2] > 32) { throw new InvalidArgumentException('Invalid CIDR.'); }
            $size = 2 ** (32 - (int)$m[2]);
            $start = (int)(floor(ip2long($m[1]) / $size) * $size); $end = $start + $size - 1;
        } elseif (preg_match('/^([0-9.]+)-([0-9.]+)$/D', $input, $m)) {
            foreach ([$m[1], $m[2]] as $ip) { if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { throw new InvalidArgumentException('Invalid IPv4.'); } }
            $start = ip2long($m[1]); $end = ip2long($m[2]);
        } elseif (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $start = $end = ip2long($input);
        } else { throw new InvalidArgumentException('Use CIDR, START-END or IPv4.'); }
        if ($end < $start || $end - $start + 1 > $maximum || !App::publicIPv4(long2ip($start)) || !App::publicIPv4(long2ip($end))) {
            throw new InvalidArgumentException('Range must be public, ordered and within configured size.');
        }
        return ['start' => $start, 'end' => $end, 'next' => $start, 'label' => long2ip($start) . '-' . long2ip($end)];
    }
}

final class VlessTemplate
{
    public static function source(string $template, string $address, string $tag): string
    {
        $template = trim($template);
        $template = str_replace('vless\\://', 'vless://', $template);
        $template = rtrim($template, '\\');
        if (!preg_match('~^(vless://[^@\s]+@)([^:/?#\s]+)(:\d+)(\?[^#\s]*)(?:#[^\s]*)?$~D', $template, $m)
            || !App::publicIPv4($address) || !preg_match('/^[a-zA-Z0-9_-]+$/D', $tag)) {
            throw new InvalidArgumentException('Invalid private VLESS template or test address.');
        }
        // Only the connection address and display fragment change. Preserve the raw query
        // byte-for-byte: TLS SNI, Host, xHTTP path, ALPN and encryption must not change.
        return $m[1] . $address . $m[3] . $m[4] . '#' . $tag;
    }
}

enum LiveVerdict
{
    case Green;
    case GreenWithDownloadError;
    case Unsuitable;
    case Inconclusive;
}

final class LiveResult
{
    public static function green(array $job, array $active, array $workers, array $checks, int $now, int $timeout): bool
    {
        return self::verdict($job, $active, $workers, $checks, $now, $timeout) === LiveVerdict::Green;
    }

    public static function verdict(array $job, array $active, array $workers, array $checks, int $now, int $timeout): LiveVerdict
    {
        if (($job['status'] ?? '') !== 'done' || (string)($job['id'] ?? '') !== (string)$active['job_id']
            || ($job['workers_done'] ?? 0) !== count($workers) || ($job['workers_total'] ?? 0) !== count($workers)
            || ($job['rounds'] ?? 0) !== 1 || (int)($job['created'] ?? 0) < $active['created_at'] - 30
            || (int)($job['created'] ?? 0) > $now + 30 || $now - $active['created_at'] > $timeout) { return LiveVerdict::Inconclusive; }
        $actualWorkers = $job['worker_ids'] ?? []; $expected = $workers;
        if (!is_array($actualWorkers)) { return LiveVerdict::Inconclusive; }
        sort($actualWorkers); sort($expected);
        if ($actualWorkers !== $expected || !is_array($job['checks'] ?? null)
            || array_diff($checks, $job['checks'])) { return LiveVerdict::Inconclusive; }
        $results = $job['results'] ?? [];
        if (!is_array($results) || count($results) !== count($workers)) { return LiveVerdict::Inconclusive; }
        $seen = [];
        $unsuitable = false;
        $downloadError = false;
        foreach ($results as $r) {
            $worker = $r['worker_id'] ?? '';
            if (!in_array($worker, $workers, true) || isset($seen[$worker])
                || ($r['round'] ?? 0) !== 1 || ($r['config']['address'] ?? '') !== $active['ip']
                || ($r['config']['name'] ?? '') !== $active['tag'] || ($r['config']['protocol'] ?? '') !== 'vless'
                || (int)($r['config']['port'] ?? 0) !== (int)$active['port']
                || ($job['claims'][$worker]['status'] ?? '') !== 'done') { return LiveVerdict::Inconclusive; }
            $seen[$worker] = true;
            $byCheck = [];
            $explicitFailure = false;
            foreach ($r['checks'] ?? [] as $c) {
                if (isset($byCheck[$c['name'] ?? ''])) { return LiveVerdict::Inconclusive; }
                $byCheck[$c['name'] ?? ''] = $c;
                $detail = (string)($c['detail'] ?? '');
                // The worker embeds the download service's HTTP error in this check.
                // A quota error from the Live API itself is handled by the request code.
                $limitedDownloadProbe = ($c['name'] ?? '') === 'download' && ($c['status'] ?? '') === 'error'
                    && preg_match('~https://speed\.cloudflare\.com/__down(?=[?\x22\x27\s]|$)~i', $detail);
                if (!$limitedDownloadProbe && preg_match('/\b429\b|rate.limit|quota|worker.offline|limit.exceeded|job.expired/i', $detail)) {
                    return LiveVerdict::Inconclusive;
                }
                if (in_array($c['name'] ?? '', array_merge(['connect'], $checks), true)
                    && in_array($c['status'] ?? '', ['down', 'blocked'], true)) { $explicitFailure = true; }
            }
            $summary = $r['summary'] ?? '';
            if (in_array($summary, ['down', 'blocked'], true)) {
                // A real probe can stop after a failed check. A bare summary is not evidence.
                if (!$explicitFailure || !isset($byCheck['connect'])) { return LiveVerdict::Inconclusive; }
                $unsuitable = true;
                continue;
            }
            if (!in_array($summary, ['ok', 'weak'], true)) { return LiveVerdict::Inconclusive; }
            foreach (array_merge(['connect'], $checks) as $name) {
                $c = $byCheck[$name] ?? [];
                // Only a reported download error can qualify for the secondary group.
                // Connection, upload and jitter still require numeric results on every node.
                if ($name === 'download' && $summary === 'ok' && ($c['status'] ?? '') === 'error') {
                    $downloadError = true;
                    continue;
                }
                $allowed = $name === 'connect' ? ['ok'] : ['ok', 'weak'];
                if (!in_array($c['status'] ?? '', $allowed, true) || !is_numeric($c['value'] ?? null)
                    || !is_finite((float)$c['value']) || (float)$c['value'] < 0
                    || (in_array($name, ['upload', 'download'], true) && (float)$c['value'] <= 0)) { return LiveVerdict::Inconclusive; }
            }
            if ($summary === 'weak') { $unsuitable = true; }
        }
        if ($unsuitable) { return LiveVerdict::Unsuitable; }
        return $downloadError ? LiveVerdict::GreenWithDownloadError : LiveVerdict::Green;
    }
}

trait LiveOperations
{
    private function initLive(): void
    {
        $this->state['live'] ??= ['active' => null, 'next_submit_at' => 0, 'blocked_until' => 0,
            'history' => [], 'observed_used' => 0, 'limit' => 60, 'needs_monitor' => false];
        $this->state['scan'] ??= ['paused' => true, 'ranges' => [], 'tested' => 0, 'passed' => 0, 'failed' => 0,
            'skipped' => 0, 'last_report' => 0, 'completion_reported' => false];
    }
    private function templateHash(): string
    {
        return hash('sha256', json_encode([$this->config['live_template'] ?? '', $this->config['live_workers'], $this->config['live_checks'], 1], JSON_THROW_ON_ERROR));
    }
    private function readyCount(): int { return count(array_filter($this->state['pool'], fn($p) => $p['status'] === 'available')); }

    private function poolDownloadGroup(array $entry): string
    {
        return $entry['download_group'] ?? (
            ($entry['via'] ?? '') === 'live-four-workers' && !empty($entry['verified_at']) ? 'complete' : 'unknown'
        );
    }

    private function poolCandidate(array $excluded = [], bool $completeOnly = false): ?string
    {
        $selected = null;
        $priority = 3;
        foreach ($this->state['pool'] as $ip => $entry) {
            if ($entry['status'] !== 'available' || in_array($ip, $excluded, true) || $this->poolIPProtected($ip)) { continue; }
            $rank = match ($this->poolDownloadGroup($entry)) {
                'complete' => 0,
                'fallback' => 2,
                default => 1,
            };
            if ($rank === 0) { return $ip; }
            if (!$completeOnly && $rank < $priority) {
                $selected = $ip;
                $priority = $rank;
            }
        }
        return $selected;
    }
    private function proofFresh(string $domain, int $now): bool
    {
        $pending = $this->state['targets'][$domain]['pending'] ?? [];
        $p = $pending['proof'] ?? [];
        return ($p['ip'] ?? '') === ($pending['new'] ?? '') && !empty($p['passed_at'])
            && $now >= $p['passed_at'] && $now - $p['passed_at'] <= $this->config['live_proof_max_age']
            && ($p['template_hash'] ?? '') === $this->templateHash();
    }
    private function cancelUnsent(string $domain): void
    {
        $p = $this->state['targets'][$domain]['pending'] ?? null;
        if (!$p || $p['attempts'] > 0) { return; } // Preserve ambiguity once a DNS write was sent.
        $active =& $this->state['live']['active'];
        if ($active && ($active['domain'] ?? '') === $domain && $active['ip'] === $p['new']) {
            $active['purpose'] = 'pool'; $active['domain'] = null;
            $this->state['pool'][$p['new']]['status'] = 'testing';
        } else { $this->state['pool'][$p['new']]['status'] = 'available'; }
        $this->state['targets'][$domain]['pending'] = null;
        $this->queue("ℹ️ خرابی {$domain} دیگر تأیید نیست؛ تعویض ارسال‌نشده لغو شد.");
    }
    private function scanRemaining(): int
    {
        return (int)array_sum(array_map(fn($r) => max(0, $r['end'] - $r['next'] + 1), $this->state['scan']['ranges']));
    }

    private function scanRangeId(array $range): string
    {
        return $range['id'] ?? substr(hash('sha256', $range['start'] . ':' . $range['end']), 0, 16);
    }

    private function scanRangeRunning(array $range): bool
    {
        $active = $this->state['live']['active'] ?? [];
        if (($active['purpose'] ?? '') !== 'scan') { return false; }
        $address = ip2long($active['ip']);
        return $address >= $range['start'] && $address <= $range['end'];
    }
    private function scanStatus(): string
    {
        $s = $this->state['scan']; $l = $this->state['live'];
        $active = $l['active'] ? $l['active']['ip'] . ' / ' . $l['active']['purpose'] : 'ندارد';
        return ($s['paused'] ? '⏸ اسکن متوقف' : '🔎 اسکن فعال') . "\nدر حال تست: {$active}\nمجموع تاریخچهٔ اسکن • تست‌شده: {$s['tested']} | پذیرفته: {$s['passed']} | رد/نامشخص: {$s['failed']} | ردشده بدون تست: {$s['skipped']}"
            . "\nباقی‌مانده: " . $this->scanRemaining() . "\nمخزن آماده: " . $this->readyCount()
            . "\nمصرف اعلام‌شده API در آخرین خواندن: {$l['observed_used']}/{$l['limit']}"
            . "\n" . ($l['blocked_until'] > time() ? 'در انتظار بازشدن سهمیه/رفع خطای API' : 'شروع تست‌ها با فاصله حداقل ۱۰ ثانیه و رعایت سقف ساعتی');
    }
    private function scanCommand(string $cmd, array $parts): string
    {
        if ($cmd === '/scanstatus') { return $this->scanStatus(); }
        if ($cmd === '/scanstop') { $this->state['scan']['paused'] = true; return '⏸ شروع IP جدید متوقف شد؛ نتیجه تست جاری دریافت می‌شود. تعویض DNS تنظیم مستقل دارد.'; }
        if ($cmd === '/scanresume') { $this->state['scan']['paused'] = false; return '▶️ اسکن رنج‌های باقی‌مانده ادامه می‌یابد.'; }
        if (!$parts || count($parts) > $this->config['scan_max_ranges']) { return 'یک رنج مثل 104.16.0.0/24 یا 104.16.0.1-104.16.0.20 وارد کنید.'; }
        try { $ranges = array_map(fn($p) => IPv4Range::parse($p, $this->config['scan_max_addresses']), $parts); }
        catch (InvalidArgumentException $e) { return 'رنج نامعتبر است؛ IPv4 عمومی، ترتیب صحیح و حداکثر ' . $this->config['scan_max_addresses'] . ' آدرس در هر رنج لازم است.'; }
        $existing = $this->state['scan']['ranges'];
        foreach ($ranges as $r) {
            foreach ($existing as $old) {
                if (max($r['start'], $old['start']) <= min($r['end'], $old['end'])) {
                    return 'این رنج با یکی از رنج‌های ثبت‌شده هم‌پوشانی دارد. برای اجرای دوباره یا حذف، «مدیریت رنج‌ها» را باز کنید.';
                }
            }
            $r['id'] = bin2hex(random_bytes(8));
            $existing[] = $r;
        }
        if (count($existing) > $this->config['scan_max_ranges']) { return 'تعداد رنج‌ها به سقف رسیده است. از «مدیریت رنج‌ها» موارد قدیمی را حذف کنید.'; }
        $this->state['scan']['ranges'] = $existing;
        $this->state['scan']['paused'] = false; $this->state['scan']['completion_reported'] = false;
        return '✅ رنج به صف اسکن اضافه شد.';
    }
    private function scanIP(): ?string
    {
        // Bounded per invocation even when a large segment is already in the pool.
        $skips = 0;
        foreach ($this->state['scan']['ranges'] as &$range) {
            while ($range['next'] <= $range['end']) {
                $ip = long2ip($range['next']);
                $inUse = in_array($ip, array_column($this->state['targets'], 'current_ip'), true);
                if (!App::publicIPv4($ip) || isset($this->state['pool'][$ip]) || $inUse) {
                    $range['next']++; $this->state['scan']['skipped']++;
                    if (++$skips >= 512) { unset($range); return null; }
                    continue;
                }
                unset($range); return $ip;
            }
        }
        unset($range); return null;
    }
    private function advanceScan(string $ip): void
    {
        $n = ip2long($ip);
        foreach ($this->state['scan']['ranges'] as &$range) {
            if ($range['next'] === $n && $n <= $range['end']) { $range['next']++; break; }
        }
        unset($range);
    }
    private function deferPreflight(array $intent, int $now, int $delay): void
    {
        $live = &$this->state['live'];
        $live['blocked_until'] = max($live['blocked_until'], $now + $delay);
        $live['scan_quota_wait'] = false;
        if ($intent['purpose'] !== 'preflight') { return; }
        $target = &$this->state['targets'][$intent['domain']];
        if (($target['pending']['new'] ?? null) !== $intent['ip']) { return; }
        if ($target['pending']['attempts'] === 0) {
            $this->state['pool'][$intent['ip']]['status'] = 'available';
            $target['pending'] = null;
        } else {
            // Keep the reservation while a previous DNS mutation may still be in flight.
            $target['pending']['proof'] = null;
            $target['pending']['live_retry_after'] = $now + $delay;
        }
    }

    private function liveFinished(LiveVerdict $verdict, int $now, string $reason): void
    {
        $active = $this->state['live']['active']; if (!$active) { return; }
        $ip = $active['ip']; $purpose = $active['purpose']; $domain = $active['domain'] ?? null;
        if (($active['template_hash'] ?? '') !== $this->templateHash()) {
            $verdict = LiveVerdict::Inconclusive;
            $reason = 'قالب کانفیگ هنگام تست تغییر کرد';
        }
        $passed = in_array($verdict, [LiveVerdict::Green, LiveVerdict::GreenWithDownloadError], true);
        $group = $verdict === LiveVerdict::GreenWithDownloadError ? 'fallback' : 'complete';
        $downloadLabel = $group === 'fallback' ? 'گروه ذخیره · خطای تست دانلود' : 'دانلود تأییدشده';
        $pending = $domain ? ($this->state['targets'][$domain]['pending'] ?? null) : null;
        if ($purpose === 'preflight' && $pending && $pending['new'] === $ip) {
            if ($passed) {
                $this->state['pool'][$ip]['download_group'] = $group;
                $this->state['pool'][$ip]['verified_at'] = $now;
                if ($group === 'fallback' && $pending['attempts'] === 0 && $this->poolCandidate(completeOnly: true) !== null) {
                    $this->state['pool'][$ip]['status'] = 'available';
                    $this->state['targets'][$domain]['pending'] = null;
                    $this->queue("↪️ {$ip} در گروه ذخیره ماند. برای {$domain} ابتدا IP دارای دانلود تأییدشده بررسی می‌شود.");
                } else {
                    $this->state['targets'][$domain]['pending']['proof'] = ['ip' => $ip, 'passed_at' => $now,
                        'job_id' => $active['job_id'], 'template_hash' => $this->templateHash(), 'download_group' => $group];
                    $this->queue("✅ تست نهایی {$ip} برای {$domain}: هر چهار نود سبز · {$downloadLabel}. در انتظار تأیید تازهٔ خرابی.");
                }
            } elseif ($verdict === LiveVerdict::Inconclusive) {
                $this->deferPreflight($active, $now, 60);
                $this->alert('live-final-inconclusive', "⏳ تست نهایی {$ip} نتیجهٔ قطعی نداشت. {$reason}\nIP در مخزن حفظ شد و ربات بعداً دوباره تلاش می‌کند.");
            } elseif ($pending['attempts'] === 0) {
                $this->state['pool'][$ip]['status'] = 'rejected';
                $this->state['targets'][$domain]['pending'] = null;
                $this->queue("❌ IP {$ip} در تست نهایی چهار نت تأیید نشد؛ DNS تغییر نکرد. {$reason}\nمخزن آماده: " . $this->readyCount());
            } else {
                // A previous PATCH may have succeeded: never release its reservation.
                $this->state['targets'][$domain]['pending']['proof'] = null;
                $this->state['targets'][$domain]['pending']['live_retry_after'] = $now + 300;
                $this->queue("⚠️ تست مجدد IP رزروشده {$ip} تأیید نشد. عملیات DNS قبلی نیاز به تطبیق دارد؛ IP رزرو باقی ماند.");
            }
            $this->state['live']['needs_monitor'] = true;
        } else {
            if ($passed) {
                // Do not overwrite a reservation or a domain assigned externally during a job.
                $status = $this->state['pool'][$ip]['status'] ?? '';
                if (in_array($status, ['', 'testing'], true) && !in_array($ip, array_column($this->state['targets'], 'current_ip'), true)) {
                    $this->state['pool'][$ip] = ['status' => 'available', 'added_at' => $now, 'verified_at' => $now,
                        'via' => 'live-four-workers', 'download_group' => $group];
                    $this->queue("💎 IP به مخزن اضافه شد: {$ip}\nچهار نود سبز · {$downloadLabel}\nموجودی آمادهٔ مخزن: " . $this->readyCount());
                } elseif ($status === 'testing' && in_array($ip, array_column($this->state['targets'], 'current_ip'), true)) {
                    $this->state['pool'][$ip]['status'] = 'used';
                }
            } elseif (($this->state['pool'][$ip]['status'] ?? '') === 'testing') { unset($this->state['pool'][$ip]); }
            if ($purpose === 'scan') {
                $this->state['scan']['tested']++;
                $this->state['scan'][$passed ? 'passed' : 'failed']++;
                $this->advanceScan($ip);
            }
        }
        $this->state['live']['active'] = null;
        $this->scanReport($now); $this->poolWarning(); $this->save();
    }
    private function scanReport(int $now): void
    {
        if (!$this->scanRemaining() && !$this->state['scan']['completion_reported'] && $this->state['scan']['ranges']) {
            $this->state['scan']['completion_reported'] = true;
            $this->state['scan']['paused'] = true;
            $this->queue("🏁 رنج‌های صف تمام شدند.\n" . $this->scanStatus());
        } elseif (!$this->state['scan']['paused'] && $now - $this->state['scan']['last_report'] >= $this->config['scan_report_seconds']) {
            $this->state['scan']['last_report'] = $now;
            $this->queue("📊 گزارش پیشرفت\n" . $this->scanStatus());
        }
    }
    private function observeMeta(array $meta, int $now): void
    {
        if (!isset($meta['limits']['per_hour'], $meta['limits']['cooldown_s'], $meta['used_last_hour'], $meta['workers'])
            || !is_numeric($meta['used_last_hour']) || (int)$meta['limits']['per_hour'] < 1) { throw new RuntimeException('Invalid live limits.'); }
        $this->state['live']['limit'] = min((int)$meta['limits']['per_hour'], $this->config['live_hourly_limit']);
        $this->state['live']['observed_used'] = (int)$meta['used_last_hour'];
        $this->state['live']['history'] = array_values(array_filter($this->state['live']['history'], fn($ts) => $ts > $now - 3600));
    }
    private function recoverSubmission(array $meta, int $now): void
    {
        $a =& $this->state['live']['active'];
        foreach ($meta['recent'] ?? [] as $recent) {
            if (!empty($recent['id']) && ($recent['source_kind'] ?? '') === 'link'
                && str_ends_with((string)($recent['source_label'] ?? ''), '#' . $a['tag'])) {
                $a['job_id'] = (string)$recent['id']; $a['phase'] = 'running'; $this->save(); return;
            }
        }
        if ($now - $a['created_at'] > $this->config['live_job_timeout']) {
            $this->liveFinished(LiveVerdict::Inconclusive, $now, 'نتیجهٔ ارسال درخواست نامشخص ماند.');
        }
    }
    public function liveStep(?int $clock = null): void
    {
        $now = $clock ?? time();
        if (($this->config['live_template'] ?? '') === '' || str_contains($this->config['live_template'], 'CHANGE_ME')) {
            if (!empty($this->state['live']['active']) || !$this->state['scan']['paused']) { $this->alert('live-template', '⛔ قالب خصوصی VLESS تنظیم نشده؛ اسکن و تست نهایی متوقف است.'); }
            $this->save(); return;
        }
        $a = $this->state['live']['active'];
        if ($a) {
            if ($now - $a['created_at'] > $this->config['live_job_timeout']) {
                $this->liveFinished(LiveVerdict::Inconclusive, $now, 'مهلت تست لایو تمام شد.');
                return;
            }
            if ($now < ($a['poll_at'] ?? 0)) { return; }
            $this->state['live']['active']['poll_at'] = $now + 10;
            try {
                if (empty($a['job_id'])) {
                    $meta = $this->api->liveMeta(); $this->observeMeta($meta, $now); $this->recoverSubmission($meta, $now);
                } else {
                    $job = $this->api->liveJob($a['job_id']);
                    if (($job['status'] ?? '') === 'done') {
                        $verdict = LiveResult::verdict($job, $a, $this->config['live_workers'], $this->config['live_checks'], $now, $this->config['live_job_timeout']);
                        $reason = $verdict === LiveVerdict::Unsuitable ? 'تست کامل بود و دست‌کم یک نود سبز نبود.' : 'نتیجهٔ معتبر و کامل دریافت نشد.';
                        $this->liveFinished($verdict, $now, $reason);
                        return;
                    }
                }
            } catch (Throwable $e) {
                if ($e instanceof HttpFailure && $e->status === 429) {
                    $delay = max(60, $e->retryAfter);
                    $this->state['live']['active']['poll_at'] = $now + $delay;
                    $this->state['live']['blocked_until'] = max($this->state['live']['blocked_until'], $now + $delay);
                    $this->state['live']['scan_quota_wait'] = false;
                }
                $this->alert('live-poll', '⚠️ دریافت نتیجه تست لایو با خطا مواجه شد؛ IP تأیید نشده و DNS از روی این تست تغییر نمی‌کند.');
            }
            $this->save(); return;
        }
        if ($now < $this->state['live']['next_submit_at']) { return; }
        $intent = null;
        if (!$this->state['paused'] && !$this->state['dry_run']) {
            foreach ($this->config['domains'] as $domain) {
                $p = $this->state['targets'][$domain]['pending'] ?? null;
                if ($p && $p['attempts'] < 3 && ($p['eligible_until'] ?? 0) >= $now && ($p['live_retry_after'] ?? 0) <= $now
                    && !$this->proofFresh($domain, $now)) {
                    $intent = ['purpose' => 'preflight', 'domain' => $domain, 'ip' => $p['new']]; break;
                }
            }
        }
        if (!$intent && !$this->state['scan']['paused']) {
            $ip = $this->scanIP();
            if ($ip !== null) { $intent = ['purpose' => 'scan', 'domain' => null, 'ip' => $ip]; }
            else { $this->scanReport($now); $this->save(); return; }
        }
        if (!$intent) { return; }
        if ($now < $this->state['live']['blocked_until']
            && !(($this->state['live']['scan_quota_wait'] ?? false) && $intent['purpose'] === 'preflight')) { return; }
        try {
            $meta = $this->api->liveMeta();
        } catch (Throwable $e) {
            $delay = $e instanceof HttpFailure && $e->status === 429 ? max(60, $e->retryAfter) : 30;
            $this->deferPreflight($intent, $now, $delay);
            $cause = $this->connectionFailure('live', $e);
            $this->alert('live-meta', "⚠️ دریافت اطلاعات API لایو ناموفق بود.\n{$cause}");
            $this->save();
            return;
        }
        $issue = $this->liveIssue($meta);
        if ($issue === null) {
            $offline = $this->offlineWorkers($meta);
            if ($offline) { $issue = 'API پاسخ داد. نودهای آماده‌نبوده: ' . implode(', ', $offline); }
        }
        if ($issue !== null) {
            $this->recordConnection('live', $issue, false);
            $this->deferPreflight($intent, $now, 30);
            $this->alert('live-meta', "⚠️ تست جدید به تعویق افتاد.\n{$issue}");
            $this->save();
            return;
        }
        $this->recordConnection('live', 'پاسخ معتبر دریافت شد. هر چهار نود آماده‌اند.', true);
        $this->observeMeta($meta, $now);
        $used = max($this->state['live']['observed_used'], count($this->state['live']['history']));
        $reserve = $intent['purpose'] === 'scan' ? $this->config['live_scan_reserve'] : 0;
        if ($used >= max(0, $this->state['live']['limit'] - $reserve)) {
            $this->deferPreflight($intent, $now, 60);
            // Do not hold emergency preflights behind a scan's reserved quota.
            $this->state['live']['scan_quota_wait'] = $intent['purpose'] === 'scan';
            $this->alert('live-quota-' . $intent['purpose'], '⏳ اسکن/تست در انتظار سهمیه API است؛ محدودیت ساعتی رعایت می‌شود. ' . ($reserve ? 'بخشی از سهمیه برای تست قبل از DNS رزرو است.' : ''));
            $this->save(); return;
        }
        $tag = 'mb-' . bin2hex(random_bytes(10));
        $this->state['live']['scan_quota_wait'] = false;
        $this->state['live']['blocked_until'] = 0;
        try { $source = VlessTemplate::source($this->config['live_template'], $intent['ip'], $tag); }
        catch (Throwable $e) { $this->alert('bad-template', '⛔ قالب کانفیگ VLESS نامعتبر است؛ فایل خصوصی config.php را بررسی کنید.'); $this->save(); return; }
        $active = $intent + ['job_id' => null, 'tag' => $tag, 'port' => (int)parse_url($source, PHP_URL_PORT),
            'created_at' => $now, 'poll_at' => $now + 10, 'phase' => 'submitting', 'template_hash' => $this->templateHash()];
        $this->state['live']['active'] = $active;
        if ($intent['purpose'] === 'scan') { $this->state['pool'][$intent['ip']] = ['status' => 'testing', 'added_at' => $now]; }
        $this->state['live']['history'][] = $now;
        $this->state['live']['next_submit_at'] = $now + max(10, $this->config['live_interval_seconds'], (int)$meta['limits']['cooldown_s']);
        // Persist unique tag and spent quota BEFORE POST. Recover a lost response by recent jobs.
        $this->save();
        try {
            $created = $this->api->liveCreate(['source' => $source, 'workers' => $this->config['live_workers'], 'rounds' => 1, 'checks' => $this->config['live_checks']]);
            if (empty($created['job_id']) || !is_string($created['job_id'])) { throw new RuntimeException('Missing job ID.'); }
            $this->state['live']['active']['job_id'] = $created['job_id'];
            $this->state['live']['active']['phase'] = 'running';
        } catch (Throwable $e) {
            if ($e instanceof HttpFailure && $e->status >= 400 && $e->status < 500 && $e->status !== 408) {
                // A definite rejection is safe to retry later; do not consume/advance this IP.
                if ($intent['purpose'] === 'scan') { unset($this->state['pool'][$intent['ip']]); }
                $this->state['live']['active'] = null;
                $this->deferPreflight($intent, $now, max(60, $e->retryAfter));
                if ($e->status === 429) { array_pop($this->state['live']['history']); }
                if ($e->status !== 429) { $this->state['scan']['paused'] = true; }
                $this->alert('live-create-rejected', '⚠️ API ایجاد تست را رد کرد (HTTP ' . $e->status . '). IP مصرف نشد؛ محدودیت یا تنظیمات را بررسی کنید.');
            } else {
                $this->alert('live-create-unknown', '⚠️ پاسخ ایجاد تست نامشخص است؛ ربات ابتدا شناسه تست را از فهرست اخیر بازیابی می‌کند و فوراً تست تکراری نمی‌سازد.');
            }
        }
        $this->save();
    }
}
