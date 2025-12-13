<?php
// This is included by tfm_core.php
// We need to grab the root path set in the index wrapper.
// Since TFM creates a new scope, we might need to rely on the fact 
// that we are including tfm_core inside index.php.

// However, TFM sets $root_path = $_SERVER['DOCUMENT_ROOT'] by default.
// We need to override it.
// The index.php wrapper sets $root_path.
// Let's ensure permissions allow www-data to read/write.
$max_upload_size_bytes = 50000000; // 50MB
?>
