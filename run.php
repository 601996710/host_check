<?php

/**
 * Domain Availability Checker
 * 支持单域名查询和批量扫描
 *
 * 单域名查询:
 *   php run.php google.com
 *
 * 批量扫描:
 *   php run.php                           # 4字母.com (aaaa~zzzz)
 *   php run.php --length=3                # 3字母
 *   php run.php --length=4 --batch=100    # 每批并发100个
 *   php run.php --length=4 --tld=xyz      # .xyz后缀
 */

// ============================================================
// 配置
// ============================================================
$length   = 5;    // 字母位数
$batch    = 50;   // 每批并发数
$tld      = 'com'; // 域名后缀
$prefix   = 'xx***';   // 固定前缀，如 aaa 或 aaa*

$singleDomain = null;

// 解析命令行参数
for ($i = 1; $i < $argc; $i++) {
    if (strpos($argv[$i], '--length=') === 0) $length = max(1, min(5, (int)substr($argv[$i], 9)));
    if (strpos($argv[$i], '--batch=') === 0)  $batch  = max(1, min(200, (int)substr($argv[$i], 8)));
    if (strpos($argv[$i], '--tld=') === 0)    $tld    = ltrim(substr($argv[$i], 6), '.');
    if (strpos($argv[$i], '--prefix=') === 0) $prefix = strtolower(trim(substr($argv[$i], 9)));
    if (strpos($argv[$i], '--') !== 0) {
        $singleDomain = strtolower(trim($argv[$i]));
    }
}

// 解析前缀：aaa* → 固定部分 aaa，可变部分自动补齐剩余位数
// 如果没有 *，整个字符串作为固定前缀
$fixedPrefix = str_replace('*', '', $prefix);
$varCount = $length - strlen($fixedPrefix);
if ($varCount < 1) $varCount = 1; // 至少1位可变

// 输出文件：前缀_位数后缀.txt（*替换为_，Windows文件名不支持*）
$filePrefix = str_replace('*', '_', $prefix ?: str_repeat('*', $length));
$batchOutputFile = __DIR__ . "/{$filePrefix}_{$length}letter_{$tld}.txt";
// 单域名查询记录到单独文件
$singleOutputFile = __DIR__ . '/available_single.txt';

// ============================================================
// RDAP 服务器配置 (HTTP-based WHOIS替代协议，更快更可靠)
// ============================================================
$RDAP_URLS = [
    'com'  => 'https://rdap.verisign.com/com/v1/domain/%s',
    'net'  => 'https://rdap.verisign.com/net/v1/domain/%s',
    'org'  => 'https://rdap.publicinterestregistry.org/rdap/domain/%s',
    'xyz'  => 'https://rdap.nic.xyz/rdap/domain/%s',
    'top'  => 'https://rdap.afilias-srs.net/rdap/top/domain/%s',
    'site' => 'https://rdap.nic.site/rdap/domain/%s',
    'win'  => 'https://rdap.nic.win/rdap/domain/%s',
    'cc'   => 'https://rdap.nic.cc/rdap/domain/%s',
    'io'   => 'https://rdap.nic.io/rdap/domain/%s',
    'me'   => 'https://rdap.nic.me/rdap/domain/%s',
    'info' => 'https://rdap.afilias.net/rdap/info/domain/%s',
    'biz'  => 'https://rdap.nic.biz/rdap/domain/%s',
    'cn'   => 'https://rdap.cnnic.cn/rdap/domain/%s',
];

// ============================================================
// 核心函数
// ============================================================

/**
 * 并发检查一批域名是否可注册 (使用curl_multi + RDAP)
 * RDAP返回HTTP 404 = 未注册(可注册), 200 = 已注册
 */
function checkBatch(array $domains, string $tld, string $rdapUrl): array
{
    $results = [];
    $mh = curl_multi_init();
    $map = []; // 用索引映射

    foreach ($domains as $i => $domain) {
        $fullDomain = $domain . '.' . $tld;
        $url = sprintf($rdapUrl, $fullDomain);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_NOBODY => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0',
        ]);
        curl_multi_add_handle($mh, $ch);
        $map[$i] = ['handle' => $ch, 'domain' => $domain];
    }

    // 并发执行所有请求
    $running = null;
    do {
        $stat = curl_multi_exec($mh, $running);
        if ($stat !== CURLM_OK) break;
        curl_multi_select($mh, 1);
    } while ($running > 0);

    // 收集结果
    foreach ($map as $item) {
        $ch = $item['handle'];
        $domain = $item['domain'];
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpCode === 404) {
            $results[$domain] = true;
        } elseif ($httpCode === 200 || $httpCode === 429) {
            $results[$domain] = false;
        } else {
            $results[$domain] = null;
        }
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }

    curl_multi_close($mh);
    return $results;
}

/**
 * 生成所有字母组合
 */
function generateCombinations(int $varCount, string $fixedPrefix = ''): Generator
{
    $total = pow(26, $varCount);
    for ($i = 0; $i < $total; $i++) {
        $suffix = '';
        $n = $i;
        for ($j = 0; $j < $varCount; $j++) {
            $suffix = chr(97 + ($n % 26)) . $suffix;
            $n = intdiv($n, 26);
        }
        yield $fixedPrefix . $suffix;
    }
}

/**
 * 格式化时间
 */
function formatTime(float $seconds): string
{
    if ($seconds < 60) return round($seconds, 1) . 's';
    $m = floor($seconds / 60);
    $s = round($seconds % 60, 1);
    return "{$m}m {$s}s";
}

/**
 * 使用WHOIS socket查询 (备用方法)
 */
function checkViaWhois(array $domains, string $tld, string $whoisServer): array
{
    $results = [];
    foreach ($domains as $domain) {
        $fullDomain = $domain . '.' . $tld;
        $sock = @fsockopen($whoisServer, 43, $errno, $errstr, 5);
        if (!$sock) {
            $results[$domain] = null;
            continue;
        }
        @fwrite($sock, $fullDomain . "\r\n");
        $data = '';
        while (!feof($sock)) {
            $data .= @fgets($sock, 4096);
        }
        fclose($sock);
        // 如果包含"No match for"说明未注册
        $results[$domain] = (stripos($data, 'No match for') !== false);
    }
    return $results;
}

// ============================================================
// 单域名查询模式
// ============================================================
if ($singleDomain) {
    // 提取域名和后缀
    if (strpos($singleDomain, '.') !== false) {
        $parts = explode('.', $singleDomain);
        $name  = $parts[0];
        $tld   = $parts[1];
    } else {
        $name = $singleDomain;
    }

    echo "查询: {$name}.{$tld} ... ";

    // 先用RDAP查
    if (isset($RDAP_URLS[$tld])) {
        $result = checkBatch([$name], $tld, $RDAP_URLS[$tld]);
        $isAvail = $result[$name] ?? null;
    } else {
        $isAvail = null;
    }

    // RDAP失败则用WHOIS socket
    if ($isAvail === null) {
        $whoisHost = "whois.nic.{$tld}";
        $result = checkViaWhois([$name], $tld, $whoisHost);
        $isAvail = $result[$name] ?? null;
    }

    if ($isAvail === true) {
        echo "[✓] 可注册!\n";
        file_put_contents($singleOutputFile, "{$name}.{$tld}" . PHP_EOL, FILE_APPEND);
    } elseif ($isAvail === false) {
        echo "[✗] 已被注册\n";
    } else {
        echo "[?] 查询失败\n";
    }
    exit(0);
}

// ============================================================
// 批量扫描模式
// ============================================================

$total = pow(26, $varCount);

echo "========================================\n";
echo "  Domain Availability Checker\n";
echo "========================================\n";
echo "  位数:       {$length}\n";
echo "  后缀:       .{$tld}\n";
echo "  前缀:       " . ($fixedPrefix ?: '(无)') . "\n";
echo "  可变位数:   {$varCount}\n";
echo "  并发数:     {$batch}\n";
echo "  总数:       " . number_format($total) . "\n";
echo "  输出文件:   {$batchOutputFile}\n";
echo "========================================\n\n";

// 检查RDAP配置
if (!isset($RDAP_URLS[$tld])) {
    echo "错误: 不支持的后缀 .{$tld}\n";
    exit(1);
}
$rdapUrl = $RDAP_URLS[$tld];

$startTime  = microtime(true);
$checked    = 0;
$available  = 0;
$lastPercent = 0;

// 清空输出文件
file_put_contents($batchOutputFile, '');

// 主循环
$generator = generateCombinations($varCount, $fixedPrefix);
$currentBatch = [];

foreach ($generator as $name) {
    $currentBatch[] = $name;

    if (count($currentBatch) >= $batch) {
        // 显示本次查询的域名
        $from = $currentBatch[0];
        $to = $currentBatch[count($currentBatch) - 1];
        echo "  查询 {$from}.{$tld} ~ {$to}.{$tld} ... ";
        $results = checkBatch($currentBatch, $tld, $rdapUrl);
        echo "完成\n";

        foreach ($currentBatch as $domain) {
            $checked++;
            $isAvail = $results[$domain] ?? null;

            if ($isAvail === true) {
                $available++;
                file_put_contents($batchOutputFile, "{$domain}.{$tld}" . PHP_EOL, FILE_APPEND);
                echo "  [✓] {$domain}.{$tld}" . PHP_EOL;
            }
        }

        $currentBatch = [];

        // 进度
        $percent = (int)($checked / $total * 100);
        if ($percent > $lastPercent) {
            $lastPercent = $percent;
            $elapsed = microtime(true) - $startTime;
            $rate = $checked / max($elapsed, 0.1);
            $remaining = ($total - $checked) / max($rate, 0.1);
            echo "\r  进度: {$percent}% | 已查: " . number_format($checked) . "/" . number_format($total) . " | 可用: {$available} | 耗时: " . formatTime($elapsed) . " | 预计剩余: " . formatTime($remaining) . str_repeat(' ', 10) . PHP_EOL;
        }
    }
}

// 处理最后一批
if (!empty($currentBatch)) {
    $from = $currentBatch[0];
    $to = $currentBatch[count($currentBatch) - 1];
    echo "  查询 {$from}.{$tld} ~ {$to}.{$tld} ... ";
    $results = checkBatch($currentBatch, $tld, $rdapUrl);
    echo "完成\n";
    foreach ($currentBatch as $domain) {
        $checked++;
        $isAvail = $results[$domain] ?? null;
        if ($isAvail === true) {
            $available++;
            file_put_contents($batchOutputFile, "{$domain}.{$tld}" . PHP_EOL, FILE_APPEND);
            echo "  [✓] {$domain}.{$tld}" . PHP_EOL;
        }
    }
}

$elapsed = microtime(true) - $startTime;
echo PHP_EOL;
echo "========================================\n";
echo "  扫描完成!\n";
echo "  总检查:   " . number_format($checked) . "\n";
echo "  可用域名: {$available}\n";
echo "  耗时:     " . formatTime($elapsed) . "\n";
echo "  结果已保存: {$batchOutputFile}\n";
echo "========================================\n";
