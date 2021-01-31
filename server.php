<?php

$payload = json_decode(file_get_contents('php://input'),true);

$fp = fsockopen($payload['server'], $payload['port']);
if (!$fp) {
    echo "Unable to open\n";
} else {
    fwrite($fp, base64_decode($payload['data']));
    stream_set_timeout($fp, 2);
    
    $content = "";
    while (true){
        $tmp = $content;
        while (!feof($fp)) {
            $content .= fread($fp, 1024);
            $stream_meta_data = stream_get_meta_data($fp); 
            if($stream_meta_data['unread_bytes'] <= 0) break; 
        }
        if ($content == $tmp) break;
    }

    fclose($fp);
    echo $content;
}