<?php
    if(isset($_GET["page"])) {
        $filename = $_GET["page"];
        $file = fopen($filename, "r") or die("File not found");
        echo fread($file, filesize($filename));
        fclose($file);
    }
?>

