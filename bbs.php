<?php
/**
 * @file bbs.php
 * @brief hash-space-bbs - データベース不要の軽量・堅牢なルーム制簡易掲示板システム
 * @details 
 * OS一時ディレクトリとJSONファイルを使用し、外部DBなしで動作します。
 * ルーム名（合言葉）はあえて完全すぎないMD5でハッシュ化しつつ、
 * ファイル競合を防ぐ排他制御（flock）やXSS・DoS対策を施した堅牢な設計です。
 * 部屋は、URLの room=<合言葉のMD5> で直接入れます（name=<名前> で名前の初期値も指定可能）。
 * @note PHP 8.3 以上を想定しています。
 * 
 * @copyright Copyright (c) 2026 Embedead-Inside
 * @license SPDX-License-Identifier: MIT-0
 */
declare(strict_types=1);

date_default_timezone_set('Asia/Tokyo');

// ==========================================
// 設定（値はすべて2のべき乗）
// ==========================================
const ROOM_MIN_BYTES = 4;        // 2^2  合言葉の最小バイト数（入室フォームで判定。ASCII 4文字 / 日本語 2文字相当）
const ROOM_MAX_BYTES = 64;       // 2^6  合言葉の最大バイト数（入室フォームで判定。ASCII 64文字 / 日本語 21文字相当）
const NAME_MAX_BYTES = 64;       // 2^6  名前の最大バイト数
const POST_MAX_BYTES = 1024;     // 2^10 本文の最大バイト数
const REQ_MAX_BYTES  = 4096;     // 2^12 リクエスト全体の最大バイト数（JSONエスケープ分を含む）
const MAX_POSTS      = 1024;     // 2^10 1ルームの最大保持件数
const MAX_ROOMS      = 256;      // 2^8  同時に存在できるルーム数
const MAX_AGE_SEC    = 1048576;  // 2^20 投稿・ルームの生存時間（約12.1日）
const COOLDOWN_SEC   = 4;        // 2^2  連投ロック時間（同一IP・同一ルーム）
const DEFAULT_LIMIT  = 16;       // 2^4  取得件数の初期値
const ROOM_PREFIX    = 'bbs_';   // 一時ファイル名の接頭辞

// ==========================================
// 共通関数
// ==========================================

/** @brief JSONを返して終了する */
function respond(array $data, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/** @brief エラーJSONを返して終了する */
function fail(string $message, int $status = 400): never
{
    respond(['error' => $message], $status);
}

/** @brief UTF-8として正しい文字列か（拡張モジュール不要） */
function isUtf8(string $s): bool
{
    return preg_match('//u', $s) === 1;
}

/** @brief 制御文字を除去し、改行をLFに統一する（多バイト文字は0x80以上なので影響なし） */
function cleanText(string $s): string
{
    $s = str_replace(["\r\n", "\r"], "\n", $s);
    return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s) ?? '';
}

/** @brief ロック済みのファイルハンドルから投稿配列を読み込む */
function loadPosts($fp): array
{
    $data = json_decode((string)stream_get_contents($fp), true);
    return is_array($data) ? $data : [];
}

/**
 * @brief クライアントに返す投稿を末尾から取り出す
 * @details 投稿は時系列順なので、古いものほど先に期限切れになります。
 *          そのため「末尾から件数分を切り出してから期限を判定」しても、
 *          「全件を判定してから切り出す」のと結果は同じで、判定は件数分で済みます。
 */
function visiblePosts(array $posts, int $limit, int $now): array
{
    $out = [];
    foreach (array_slice($posts, -$limit) as $p) {
        if ($now - ($p['ts'] ?? 0) < MAX_AGE_SEC) {
            $out[] = ['name' => $p['name'] ?? '名無し', 'content' => $p['content'], 'time' => $p['time']];
        }
    }
    return $out;
}

// ==========================================
// サーバー処理（APIモード）
// ==========================================
if (isset($_GET['action'])) {
    header('Cache-Control: no-store');
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');

    $action = $_GET['action'];
    if (!in_array($action, ['read', 'send'], true)) {
        fail('不正なアクションです。');
    }

    /**
     * @brief 防御策①：ルーム（合言葉のMD5）のバリデーション
     * @details room には合言葉そのものではなく、32桁の16進数（MD5）を受け取ります。
     *          形式が固定なので、パストラバーサルや不正な文字は入り込めません。
     */
    $roomHash = $_GET['room'] ?? '';
    if (!is_string($roomHash) || !preg_match('/^[0-9a-f]{32}$/iD', $roomHash)) {
        fail('不正なルームです。');
    }
    $roomHash = strtolower($roomHash);

    /**
     * @brief 一時ファイル名
     * @details MD5は入室フォームで合言葉から作ります。あえて完全すぎないMD5を用いることで、
     *          ファイル構造の「手作り感」を残しつつ一意化します。
     */
    $tmpFile = sys_get_temp_dir() . '/' . ROOM_PREFIX . $roomHash;
    $now     = time();

    // 取得件数（1〜MAX_POSTS に丸める）
    $limitParam = $_GET['limit'] ?? '';
    $limit = (is_string($limitParam) && ctype_digit($limitParam))
        ? max(1, min(MAX_POSTS, (int)$limitParam))
        : DEFAULT_LIMIT;

    /**
     * @brief ① 読み込み処理（アクション：read）
     * @details 共有ロック（LOCK_SH）で読むだけです。ファイルは書き換えません。
     *          最も頻繁に呼ばれる処理なので、書き込みを無くして競合と処理時間を減らしています。
     */
    if ($action === 'read') {
        $posts = [];
        if ($fp = @fopen($tmpFile, 'rb')) {
            if (flock($fp, LOCK_SH)) {
                $posts = loadPosts($fp);
            }
            fclose($fp); // 閉じるとロックも解除される
        }
        respond(visiblePosts($posts, $limit, $now));
    }

    /**
     * @brief ② メッセージ送信処理（アクション：send）
     * @details 排他ロック（LOCK_EX）の中で「読み込み→追加→書き込み」を行い、
     *          同時書き込みによるデータ破損（レースコンディション）を防ぎます。
     */
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        fail('POSTで呼び出してください。', 405);
    }

    // 防御策②：リクエスト全体のサイズチェック（宣言された長さと、実際に読んだ長さの両方）
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > REQ_MAX_BYTES) {
        fail('リクエストサイズが大きすぎます。', 413);
    }
    $raw = (string)file_get_contents('php://input', false, null, 0, REQ_MAX_BYTES + 1);
    if (strlen($raw) > REQ_MAX_BYTES) {
        fail('リクエストサイズが大きすぎます。', 413);
    }

    // 防御策③：型・文字コード・サイズのチェック
    $input    = json_decode($raw, true);
    $name     = $input['name'] ?? null;
    $content  = $input['content'] ?? null;
    if (!is_string($name) || !is_string($content) || !isUtf8($name) || !isUtf8($content)) {
        fail('不正なリクエストです。');
    }

    $content  = trim(cleanText($content));
    $name     = trim((string)preg_replace('/\s+/u', ' ', cleanText($name)));
    if ($name === '') {
        $name = '名無し';
    }
    if ($content === '') {
        fail('本文が空です。');
    }
    if (strlen($content) > POST_MAX_BYTES || strlen($name) > NAME_MAX_BYTES) {
        fail('送信サイズ制限を超えています。', 413);
    }

    /**
     * @brief 防御策④：ルーム数の制限と古いルームの掃除
     * @details 一覧取得（glob）は重いので、新規ルーム作成時と、まれに（1/32）だけ行います。
     */
    $isNewRoom = !is_file($tmpFile);
    if ($isNewRoom || random_int(1, 32) === 1) {
        $files = glob(sys_get_temp_dir() . '/' . ROOM_PREFIX . '*') ?: [];
        foreach ($files as $i => $f) {
            if ($now - (int)@filemtime($f) >= MAX_AGE_SEC) {
                @unlink($f);
                unset($files[$i]);
            }
        }
        if ($isNewRoom && count($files) >= MAX_ROOMS) {
            fail('現在、新しいルームを作成できません。しばらくしてからお試しください。', 503);
        }
    }

    $fp = @fopen($tmpFile, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        fail('サーバー内部エラーが発生しました。', 500);
    }
    if ($isNewRoom) {
        @chmod($tmpFile, 0600);
    }

    $posts = loadPosts($fp);

    /**
     * @brief 防御策⑤：サーバー側の連投ロック
     * @details 同一IP・同一ルームの投稿を、直近COOLDOWN_SEC秒分だけ末尾から調べます。
     *          IPはルームのハッシュと混ぜた8文字の短縮ハッシュで保持します。
     */
    $ih = substr(md5(($_SERVER['REMOTE_ADDR'] ?? '') . $roomHash), 0, 8);
    for ($i = count($posts) - 1; $i >= 0 && $now - ($posts[$i]['ts'] ?? 0) < COOLDOWN_SEC; $i--) {
        if (($posts[$i]['ih'] ?? '') === $ih) {
            fail('連投は禁止されています。あと' . (COOLDOWN_SEC - ($now - $posts[$i]['ts'])) . '秒ほど待ってください。', 429);
        }
    }

    // 新規投稿を追加（生データで保存。画面側で textContent を使うためXSSになりません）
    $posts[] = [
        'name'     => $name,
        'content'  => $content,
        'time'     => date('Y/m/d H:i:s', $now),
        'ts'       => $now,
        'ih'       => $ih,
    ];

    // 期限切れを捨て、最大件数を超えた古い投稿を押し出す
    $posts = array_values(array_filter($posts, fn($p) => $now - ($p['ts'] ?? 0) < MAX_AGE_SEC));
    if (count($posts) > MAX_POSTS) {
        $posts = array_slice($posts, -MAX_POSTS);
    }

    // 日本語を \uXXXX にしない（1文字6バイト→3バイト）ことで、ファイルサイズと読み書き時間を半減
    $json = json_encode($posts, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        fail('サーバー内部エラーが発生しました。', 500);
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, $json);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    respond(['success' => true, 'posts' => visiblePosts($posts, $limit, $now)]);
}

// ==========================================
// 入室フォーム（合言葉 → MD5 → ?room=<MD5> のURLへ移動）
// ==========================================
/**
 * @brief 合言葉をMD5にして、部屋のURLへリダイレクトする
 * @details 合言葉はPOSTの本文で送るため、URL・履歴・アクセスログには残りません。
 *          以降はURLの room=<MD5> だけで部屋に入れます。
 */
$entranceError = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pass'])) {
    $pass = is_string($_POST['pass']) ? trim($_POST['pass']) : '';
    $passLen = strlen($pass);
    if ($passLen < ROOM_MIN_BYTES || $passLen > ROOM_MAX_BYTES) {
        $entranceError = '合言葉は' . ROOM_MIN_BYTES . '〜' . ROOM_MAX_BYTES . 'バイトで入力してください（日本語は1文字3バイト）。';
    } else {
        $query = ['room' => md5($pass)];
        $limitParam = $_POST['limit'] ?? '';
        if (is_string($limitParam) && ctype_digit($limitParam) && (int)$limitParam !== DEFAULT_LIMIT) {
            $query['limit'] = max(1, min(MAX_POSTS, (int)$limitParam));
        }
        header('Location: ?' . http_build_query($query), true, 303);
        exit;
    }
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
?>
<!-- ==========================================
     画面処理（HTML / JavaScript クライアント）
     ========================================== -->
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>hash-space-bbs</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 10px auto; padding: 10px; background: #fafafa; color: #222; }
        .card { background: white; padding: 15px; border-radius: 8px; border: 1px solid #ddd; }
        .hidden { display: none; }
        input[type="text"], textarea { width: 100%; padding: 10px; box-sizing: border-box; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; }
        button { background: #333; color: white; border: none; padding: 10px; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; font-weight: bold; }
        button:disabled { opacity: 0.5; cursor: default; }
        .post { background: #fdfdfd; padding: 10px; border-radius: 4px; margin-bottom: 8px; border: 1px solid #eee; }
        .post-meta { display: flex; justify-content: space-between; font-size: 0.75rem; color: #666; margin-bottom: 4px; }
        .name { font-weight: bold; color: #0056b3; }
        .post-body { white-space: pre-wrap; word-break: break-all; font-size: 15px; line-height: 1.4; }
        .empty { font-size: 0.8rem; color: #aaa; text-align: center; }
        .error { color: #c00; font-size: 0.85rem; margin: 0 0 10px; }
    </style>
</head>
<body>

    <!-- エントランス画面（合言葉を送ると、サーバーがMD5にして ?room=<MD5> のURLへ移動します） -->
    <form id="entrance" class="card" method="post">
        <h3>hash-space-bbs</h3>
        <?php if ($entranceError !== ''): ?>
        <p class="error"><?= htmlspecialchars($entranceError, ENT_QUOTES, 'UTF-8') ?></p>
        <?php endif; ?>
        <input type="text" name="pass" placeholder="合言葉（4〜64バイト）" autocomplete="off" required>
        <label style="font-size:0.8rem; color:#666;">Web表示件数:</label>
        <select name="limit" style="padding:5px; margin-bottom:10px;">
            <option value="8">8件</option>
            <option value="16" selected>16件</option>
            <option value="32">32件</option>
            <option value="64">64件</option>
        </select>
        <button type="submit">入室する</button>
    </form>

    <!-- BBS画面（URLの ?room=<MD5> で直接入室。退室は「戻る」、更新は「更新」のブラウザ機能を使います） -->
    <div id="room" class="card hidden">
        <input type="text" id="nameInput" placeholder="名前（省略すると名無し）">
        <textarea id="msgInput" placeholder="本文を入力してください (最大1,024バイトまで)" rows="4"></textarea>
        <button id="sendBtn" onclick="send()">書き込む</button>
        <div id="posts" style="margin-top: 15px;"></div>
    </div>

<script>
    let roomName = "";      // 部屋（合言葉のMD5）
    let displayLimit = 16;
    let lastSendTime = 0;

    // サーバー（PHP側）の設定と同じ値です
    const NAME_MAX_BYTES = 64;    // 2^6
    const POST_MAX_BYTES = 1024;  // 2^10
    const COOLDOWN_MS = 4000;     // 2^2 秒（サーバー側でも同じ制限をかけています）

    /** UTF-8でのバイト数（サーバーの strlen と同じ基準） */
    const byteLen = (s) => new TextEncoder().encode(s).length;

    /** 要素を作って textContent で文字を入れる（HTMLとして解釈されないのでXSSになりません） */
    const el = (tag, cls, text) => {
        const e = document.createElement(tag);
        e.className = cls;
        e.textContent = text;
        return e;
    };

    /**
     * API呼び出しの共通処理
     * 通信失敗・不正な応答・サーバーのエラーJSONをすべて Error に統一します。
     */
    async function api(query, options) {
        let data;
        try {
            const res = await fetch('?' + query, options);
            data = await res.json();
        } catch (e) {
            throw new Error('通信に失敗しました。');
        }
        if (data?.error) throw new Error(data.error);
        return data;
    }

    /**
     * 投稿一覧の非同期取得処理
     */
    async function readPosts() {
        try {
            const posts = await api(`action=read&room=${roomName}&limit=${displayLimit}`);
            renderPosts(posts);
        } catch (e) {
            alert(e.message);
        }
    }

    /**
     * メッセージ送信処理（クールダウン・サイズチェック付き）
     * 名前が空のときは、サーバー側で「名無し」になります。
     */
    async function send() {
        const name = document.getElementById('nameInput').value.trim();
        const content = document.getElementById('msgInput').value.trim();
        if (!content) return;

        if (Date.now() - lastSendTime < COOLDOWN_MS) {
            alert("連投は禁止されています。数秒待ってから送信してください。");
            return;
        }
        if (byteLen(name) > NAME_MAX_BYTES) {
            alert("名前が長すぎます（最大64バイト）。");
            return;
        }
        if (byteLen(content) > POST_MAX_BYTES) {
            alert("投稿サイズが1,024バイトを超えています。");
            return;
        }

        const btn = document.getElementById('sendBtn');
        btn.disabled = true;
        try {
            const data = await api(`action=send&room=${roomName}&limit=${displayLimit}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, content })
            });
            lastSendTime = Date.now();
            renderPosts(data.posts);
            document.getElementById('msgInput').value = "";
            rememberName(name);
        } catch (e) {
            alert(e.message);
        } finally {
            btn.disabled = false; // 通信エラーでも必ずボタンを戻す
        }
    }

    /**
     * 入力した名前をURLの name= に反映する（ブラウザで「更新」しても名前が残ります）
     */
    function rememberName(name) {
        const url = new URL(location.href);
        if (name) url.searchParams.set('name', name);
        else url.searchParams.delete('name');
        history.replaceState(history.state, '', url);
    }

    /**
     * 投稿データの画面描画処理
     */
    function renderPosts(posts) {
        const area = document.getElementById('posts');
        area.replaceChildren();

        if (posts.length === 0) {
            area.append(el('p', 'empty', 'まだ書き込みはありません。'));
            return;
        }

        for (const p of posts.slice().reverse()) {
            const meta = el('div', 'post-meta', '');
            meta.append(el('span', 'name', p.name), el('span', '', p.time));

            const div = el('div', 'post', '');
            div.append(meta, el('div', 'post-body', p.content));
            area.append(div);
        }
    }

    // URLの ?room=<MD5> があれば、その部屋に直接入る（name= は名前欄の初期値、limit= は表示件数）
    const params = new URLSearchParams(location.search);
    const roomParam = params.get('room') ?? '';
    if (/^[0-9a-f]{32}$/i.test(roomParam)) {
        roomName = roomParam.toLowerCase();
        displayLimit = parseInt(params.get('limit') ?? '', 10) || 16;
        document.getElementById('nameInput').value = params.get('name') ?? '';

        document.getElementById('entrance').classList.add('hidden');
        document.getElementById('room').classList.remove('hidden');
        readPosts();
    }
</script>
</body>
</html>
