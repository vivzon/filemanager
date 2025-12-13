<?php
session_start();

// 1. Security Check - No session required files
if (!isset($_SESSION["client_user"]) && !isset($_SESSION["admin_user"])) {
    header("Location: /login.php");
    exit();
}

// 2. Define Root Path based on session
if (isset($_SESSION["admin_user"])) {
    $root_path = "/var/www/clients";
} else {
    $cuser = $_SESSION["client_user"];
    $root_path = "/var/www/clients/$cuser";
}

// 3. Ensure Directory Exists
if (!file_exists($root_path)) {
    mkdir($root_path, 0755, true);
}

// TEMP: show any PHP errors directly on the page while debugging.
// Remove or comment these three lines after it works.
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ALL);

// Increase file size limits for this script
ini_set('upload_max_filesize', '500M');
ini_set('post_max_size', '500M');
ini_set('max_execution_time', '300');
ini_set('max_input_time', '300');

// MAPPING: Map your root_path to the file manager's base_path variable
$base_path = rtrim($root_path, '/');

/**
 * Helper: nice file size
 */
if (!function_exists('format_file_size')) {
    function format_file_size($bytes)
    {
        if (!is_numeric($bytes) || $bytes <= 0) {
            return '0 B';
        }
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $power = floor(log($bytes, 1024));
        $power = min($power, count($units) - 1);
        return round($bytes / pow(1024, $power), 2) . ' ' . $units[$power];
    }
}

/**
 * Helper: change file permissions safely
 */
if (!function_exists('change_file_permissions')) {
    function change_file_permissions($path, $permissions)
    {
        $permissions = trim($permissions);
        $permissions = ltrim($permissions, '0');
        if ($permissions === '') {
            $permissions = '0';
        }
        if (!preg_match('/^[0-7]{3,4}$/', $permissions)) {
            return false;
        }
        $mode = octdec($permissions);
        return @chmod($path, $mode);
    }
}

/**
 * Helper: recursive delete (file or directory)
 */
function shm_rrmdir($path)
{
    if (!file_exists($path)) {
        return true;
    }
    if (!is_dir($path)) {
        return @unlink($path);
    }
    $items = scandir($path);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $sub = $path . DIRECTORY_SEPARATOR . $item;
        if (is_dir($sub)) {
            shm_rrmdir($sub);
        } else {
            @unlink($sub);
        }
    }
    return @rmdir($path);
}

/**
 * Helper: normalize a relative path (remove .., .)
 */
function shm_normalize_relative($path)
{
    $path = str_replace('\\', '/', $path);
    $path = '/' . ltrim($path, '/');
    $parts = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($parts);
        } else {
            $parts[] = $part;
        }
    }
    return '/' . implode('/', $parts);
}

/**
 * Helper: build safe absolute path inside base
 */
function shm_build_path($base, $relative)
{
    $base = rtrim(str_replace('\\', '/', $base), '/');
    $relative = shm_normalize_relative($relative);
    $full = $base . $relative;

    // If it exists, use realpath to ensure not escaping
    if (file_exists($full)) {
        $real = realpath($full);
        if ($real === false) {
            return false;
        }
        $real = str_replace('\\', '/', $real);
        if (strpos($real, $base) !== 0) {
            return false;
        }
        return $real;
    }

    // If it doesn't exist yet (e.g., new folder), still ensure prefix
    $normalized = str_replace('\\', '/', $full);
    if (strpos($normalized, $base) !== 0) {
        return false;
    }
    return $normalized;
}

/**
 * Helper: recursive copy directory
 */
function shm_rcopy($src, $dst)
{
    if (is_dir($src)) {
        if (!file_exists($dst)) {
            @mkdir($dst, 0755, true);
        }
        $items = scandir($src);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $src_item = $src . '/' . $item;
            $dst_item = $dst . '/' . $item;
            if (is_dir($src_item)) {
                shm_rcopy($src_item, $dst_item);
            } else {
                @copy($src_item, $dst_item);
            }
        }
        return true;
    } elseif (is_file($src)) {
        return @copy($src, $dst);
    }
    return false;
}

/**
 * Helper to recursively add a directory to a zip archive.
 */
function add_directory_to_zip(ZipArchive &$zip, $dir_path, $zip_path_prefix) {
    $zip->addEmptyDir($zip_path_prefix);
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir_path, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($files as $file) {
        if (!$file->isDir()) {
            $file_path = $file->getRealPath();
            $relative_path = $zip_path_prefix . '/' . substr($file_path, strlen($dir_path) + 1);
            $zip->addFile($file_path, str_replace('\\', '/', $relative_path));
        }
    }
}

/**
 * Helper: create zip archive from multiple files/folders
 */
function shm_create_zip_from_multiple($sources, $destination) {
    if (!extension_loaded('zip') || empty($sources)) {
        return false;
    }
    $zip = new ZipArchive();
    if ($zip->open($destination, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        return false;
    }
    foreach ($sources as $source_path) {
        if (!file_exists($source_path)) continue;

        $base_name = basename($source_path);

        if (is_file($source_path)) {
            $zip->addFile($source_path, $base_name);
        } elseif (is_dir($source_path)) {
            add_directory_to_zip($zip, $source_path, $base_name);
        }
    }
    return $zip->close();
}


/**
 * Helper: create zip archive (single)
 */
function shm_create_zip($source, $destination)
{
    if (!extension_loaded('zip')) {
        return false;
    }

    if (!file_exists($source)) {
        return false;
    }

    $zip = new ZipArchive();
    if ($zip->open($destination, ZIPARCHIVE::CREATE) !== true) {
        return false;
    }

    $source = str_replace('\\', '/', realpath($source));

    if (is_dir($source)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($files as $file) {
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();
                $relativePath = substr($filePath, strlen($source) + 1);
                $zip->addFile($filePath, $relativePath);
            }
        }
    } elseif (is_file($source)) {
        $zip->addFile($source, basename($source));
    }

    return $zip->close();
}

/**
 * Helper: extract zip archive
 */
function shm_extract_zip($zip_path, $extract_to)
{
    if (!extension_loaded('zip')) {
        return false;
    }

    if (!file_exists($zip_path)) {
        return false;
    }

    $zip = new ZipArchive();
    if ($zip->open($zip_path) !== true) {
        return false;
    }

    if (!file_exists($extract_to)) {
        @mkdir($extract_to, 0755, true);
    }

    $result = $zip->extractTo($extract_to);
    $zip->close();

    return $result;
}

/**
 * Helper: get directory tree for path selection
 */
function get_directory_tree($base_path, $current_path = '/', $level = 0) {
    $tree = [];
    $full_path = shm_build_path($base_path, $current_path);
    
    if (is_dir($full_path)) {
        $items = scandir($full_path);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            
            $item_path = $current_path . '/' . $item;
            $item_full_path = shm_build_path($base_path, $item_path);
            
            if (is_dir($item_full_path)) {
                $tree[] = [
                    'path' => $item_path,
                    'name' => $item,
                    'level' => $level,
                    'children' => get_directory_tree($base_path, $item_path, $level + 1)
                ];
            }
        }
    }
    
    return $tree;
}

function sanitize_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// ------------- INPUTS -------------
$current_path = isset($_GET['path']) ? $_GET['path'] : '/';
$current_path = shm_normalize_relative($current_path);
$search_query = isset($_GET['q']) ? trim($_GET['q']) : '';
$sort         = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$view_mode    = 'list';

$files     = [];
$directory_tree = [];

// Full path of current folder
$full_path = shm_build_path($base_path, $current_path . '/');

if ($full_path === false) {
    die("Invalid path - Security Restriction");
}

// Get directory tree for path selection
$directory_tree = get_directory_tree($base_path, '/');

// -------- FILE OPERATIONS (POST) --------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Multi-file upload (Enhanced for AJAX)
    if (isset($_POST['upload_files']) && isset($_FILES['files'])) {
        $target_dir = rtrim($full_path, '/') . '/';
        $uploaded = 0;
        $failed = 0;
        $errors = [];
        
        foreach ($_FILES['files']['name'] as $key => $name) {
            if ($_FILES['files']['error'][$key] === UPLOAD_ERR_OK) {
                $target_file = $target_dir . basename($name);
                
                if ($_FILES['files']['size'][$key] > 500 * 1024 * 1024) {
                    $failed++;
                    $errors[] = "File '$name' is too large.";
                    continue;
                }
                
                if (move_uploaded_file($_FILES['files']['tmp_name'][$key], $target_file)) {
                    $uploaded++;
                } else {
                    $failed++;
                    $errors[] = "Failed to move uploaded file '$name'.";
                }
            } else {
                    $failed++;
                    $errors[] = "Error uploading file '$name'. Code: " . $_FILES['files']['error'][$key];
            }
        }
        
        $msg = "Uploaded {$uploaded} files" . ($failed > 0 ? ", {$failed} failed" : "");

        // Return JSON for AJAX requests, otherwise redirect
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            if ($failed > 0) {
                    echo json_encode(['success' => false, 'message' => $msg, 'errors' => $errors]);
            } else {
                    echo json_encode(['success' => true, 'message' => $msg]);
            }
            exit;
        } else {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode($msg));
                exit;
        }
    }


    // Create folder
    if (isset($_POST['create_folder'])) {
        $folder_name = sanitize_input($_POST['folder_name']);
        $folder_name = trim(str_replace(['/', '\\'], '', $folder_name));
        if ($folder_name !== '') {
            $rel = ($current_path === '/' ? '' : $current_path) . '/' . $folder_name;
            $new_abs = shm_build_path($base_path, $rel);
            if ($new_abs !== false && !file_exists($new_abs)) {
                @mkdir($new_abs, 0755, true);
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Folder created'));
                exit;
            } else {
                header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Folder already exists or invalid path'));
                exit;
            }
        }
    }

    // Create file
    if (isset($_POST['create_file'])) {
        $file_name = sanitize_input($_POST['file_name']);
        $file_name = trim(str_replace(['/', '\\'], '', $file_name));
        if ($file_name !== '') {
            $rel = ($current_path === '/' ? '' : $current_path) . '/' . $file_name;
            $new_abs = shm_build_path($base_path, $rel);
            if ($new_abs !== false && !file_exists($new_abs)) {
                if (@file_put_contents($new_abs, '') !== false) {
                    header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('File created'));
                    exit;
                }
            }
            header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('File already exists or invalid path'));
            exit;
        }
    }

    // Change permissions
    if (isset($_POST['change_permissions'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $permissions   = sanitize_input($_POST['permissions']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        if ($target_abs !== false && file_exists($target_abs)) {
            if (change_file_permissions($target_abs, $permissions)) {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Permissions changed'));
                exit;
            } else {
                header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to change permissions'));
                exit;
            }
        }
    }

    // Delete file / folder
    if (isset($_POST['delete_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        if ($target_abs !== false && file_exists($target_abs)) {
            $ok = shm_rrmdir($target_abs);
            $msg = $ok ? 'Item deleted' : 'Failed to delete item';
            header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode($msg));
            exit;
        }
    }

    // Rename
    if (isset($_POST['rename_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $new_name      = sanitize_input($_POST['new_name']);
        $new_name      = trim(str_replace(['/', '\\'], '', $new_name));

        if ($new_name !== '') {
            $old_abs = shm_build_path($base_path, $file_path_rel);
            if ($old_abs !== false && file_exists($old_abs)) {
                $dir_rel = trim(str_replace('\\', '/', dirname($file_path_rel)), '/');
                $new_rel = ($dir_rel ? '/' . $dir_rel : '') . '/' . $new_name;
                $new_abs = shm_build_path($base_path, $new_rel);
                if ($new_abs !== false) {
                    if (@rename($old_abs, $new_abs)) {
                        header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Item renamed'));
                        exit;
                    } else {
                        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to rename item'));
                        exit;
                    }
                }
            }
        }
    }

    // Copy
    if (isset($_POST['copy_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_path   = sanitize_input($_POST['target_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        $dest_abs      = shm_build_path($base_path, $target_path . '/' . basename($file_path_rel));
        
        if ($target_abs !== false && file_exists($target_abs) && $dest_abs !== false) {
            if (is_dir($target_abs)) {
                $success = shm_rcopy($target_abs, $dest_abs);
            } else {
                $success = @copy($target_abs, $dest_abs);
            }
            
            if ($success) {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Item copied successfully'));
                exit;
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to copy item'));
        exit;
    }

    // Move
    if (isset($_POST['move_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_path   = sanitize_input($_POST['target_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        $dest_abs      = shm_build_path($base_path, $target_path . '/' . basename($file_path_rel));
        
        if ($target_abs !== false && file_exists($target_abs) && $dest_abs !== false) {
            if (@rename($target_abs, $dest_abs)) {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Item moved successfully'));
                exit;
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to move item'));
        exit;
    }

    // Zip Single Item
    if (isset($_POST['zip_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        
        if ($target_abs !== false && file_exists($target_abs)) {
            $zip_name = basename($file_path_rel) . '.zip';
            $zip_rel = ($current_path === '/' ? '' : $current_path) . '/' . $zip_name;
            $zip_abs = shm_build_path($base_path, $zip_rel);
            
            if ($zip_abs !== false && shm_create_zip($target_abs, $zip_abs)) {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Item zipped successfully'));
                exit;
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to create zip'));
        exit;
    }

    // Zip Multiple Selected Items
    if (isset($_POST['zip_selected'])) {
        $selected_paths_rel = isset($_POST['selected_paths']) && is_array($_POST['selected_paths']) ? $_POST['selected_paths'] : [];
        $zip_name = sanitize_input($_POST['zip_name']);
        // Sanitize and ensure .zip extension
        $zip_name = preg_replace('/[^a-zA-Z0-9\._-]/', '', $zip_name);
        if (substr($zip_name, -4) !== '.zip') {
            $zip_name .= '.zip';
        }
        
        if (!empty($selected_paths_rel) && !empty($zip_name)) {
            $absolute_paths = [];
            foreach ($selected_paths_rel as $rel_path) {
                $abs_path = shm_build_path($base_path, $rel_path);
                if ($abs_path !== false) {
                    $absolute_paths[] = $abs_path;
                }
            }

            if (!empty($absolute_paths)) {
                $zip_destination_rel = ($current_path === '/' ? '' : $current_path) . '/' . $zip_name;
                $zip_destination_abs = shm_build_path($base_path, $zip_destination_rel);

                if ($zip_destination_abs !== false && shm_create_zip_from_multiple($absolute_paths, $zip_destination_abs)) {
                    header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('Archive created successfully.'));
                    exit;
                }
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to create zip from selected items.'));
        exit;
    }

    // Unzip
    if (isset($_POST['unzip_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        
        if ($target_abs !== false && file_exists($target_abs)) {
            $extract_to = dirname($target_abs) . '/' . pathinfo($target_abs, PATHINFO_FILENAME);
            if (shm_extract_zip($target_abs, $extract_to)) {
                header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode('File unzipped successfully'));
                exit;
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Failed to unzip file'));
        exit;
    }

    // Download
    if (isset($_POST['download_path'])) {
        $file_path_rel = sanitize_input($_POST['file_path']);
        $target_abs    = shm_build_path($base_path, $file_path_rel);
        
        if ($target_abs !== false && file_exists($target_abs)) {
            if (is_dir($target_abs)) {
                // Create zip for download
                $zip_name = basename($file_path_rel) . '.zip';
                $zip_path = sys_get_temp_dir() . '/' . $zip_name;
                
                if (shm_create_zip($target_abs, $zip_path)) {
                    header('Content-Type: application/zip');
                    header('Content-Disposition: attachment; filename="' . $zip_name . '"');
                    header('Content-Length: ' . filesize($zip_path));
                    readfile($zip_path);
                    unlink($zip_path);
                    exit;
                }
            } else {
                // Download single file
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($target_abs) . '"');
                header('Content-Length: ' . filesize($target_abs));
                readfile($target_abs);
                exit;
            }
        }
        header('Location: index.php?path=' . urlencode($current_path) . '&error=' . urlencode('Download failed'));
        exit;
    }

    // Delete Selected
    if (isset($_POST['delete_selected'])) {
        $paths = isset($_POST['selected_paths']) && is_array($_POST['selected_paths']) ? $_POST['selected_paths'] : [];
        $deleted_count = 0;
        if (!empty($paths)) {
            foreach ($paths as $rel_path) {
                $abs_path = shm_build_path($base_path, $rel_path);
                if ($abs_path && shm_rrmdir($abs_path)) {
                    $deleted_count++;
                }
            }
        }
        $msg = $deleted_count > 0 ? "Successfully deleted {$deleted_count} items." : "Failed to delete items.";
        header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode($msg));
        exit;
    }

    // Copy Selected
    if (isset($_POST['copy_selected'])) {
        $paths = isset($_POST['selected_paths']) && is_array($_POST['selected_paths']) ? $_POST['selected_paths'] : [];
        $target_path = sanitize_input($_POST['target_path']);
        $copied_count = 0;
        if (!empty($paths)) {
            foreach ($paths as $rel_path) {
                $src_abs = shm_build_path($base_path, $rel_path);
                $dest_abs = shm_build_path($base_path, $target_path . '/' . basename($rel_path));
                if ($src_abs && $dest_abs) {
                    if (is_dir($src_abs)) {
                        if (shm_rcopy($src_abs, $dest_abs)) $copied_count++;
                    } else {
                        if (@copy($src_abs, $dest_abs)) $copied_count++;
                    }
                }
            }
        }
        $msg = $copied_count > 0 ? "Successfully copied {$copied_count} items." : "Failed to copy items.";
        header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode($msg));
        exit;
    }

    // Move Selected
    if (isset($_POST['move_selected'])) {
        $paths = isset($_POST['selected_paths']) && is_array($_POST['selected_paths']) ? $_POST['selected_paths'] : [];
        $target_path = sanitize_input($_POST['target_path']);
        $moved_count = 0;
        if (!empty($paths)) {
            foreach ($paths as $rel_path) {
                $src_abs = shm_build_path($base_path, $rel_path);
                $dest_abs = shm_build_path($base_path, $target_path . '/' . basename($rel_path));
                if ($src_abs && $dest_abs && @rename($src_abs, $dest_abs)) {
                    $moved_count++;
                }
            }
        }
        $msg = $moved_count > 0 ? "Successfully moved {$moved_count} items." : "Failed to move items.";
        header('Location: index.php?path=' . urlencode($current_path) . '&success=' . urlencode($msg));
        exit;
    }

}

// -------- BUILD FILE LIST --------
if (is_dir($full_path)) {
    $items = scandir($full_path);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $abs = rtrim($full_path, '/') . '/' . $item;
        $is_dir = is_dir($abs);

        // relative path from domain root, always starting with '/'
        $rel = ($current_path === '/' ? '' : $current_path) . '/' . $item;
        $rel = shm_normalize_relative($rel);

        $size = 0;
        if (!$is_dir) {
            $size = @filesize($abs);
        }

        $perm = @fileperms($abs);
        $perm = $perm ? substr(sprintf('%o', $perm), -4) : '----';

        $files[] = [
            'name'        => $item,
            'relative'    => $rel,
            'is_dir'      => $is_dir,
            'size'        => $size,
            'permissions' => $perm,
            'modified'    => date('Y-m-d H:i:s', @filemtime($abs)),
            'extension'   => $is_dir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION)),
        ];
    }
}

// Sort: dirs first, then by selected field
usort($files, function ($a, $b) use ($sort) {
    if ($a['is_dir'] && !$b['is_dir']) return -1;
    if (!$a['is_dir'] && $b['is_dir']) return 1;

    switch ($sort) {
        case 'size':
            return $a['size'] <=> $b['size'];
        case 'modified':
            return strcmp($a['modified'], $b['modified']);
        case 'type':
            return strcmp($a['extension'], $b['extension']);
        case 'name':
        default:
            return strcasecmp($a['name'], $b['name']);
    }
});

// Search filter
if ($search_query !== '') {
    $q = strtolower($search_query);
    $files = array_filter($files, function ($f) use ($q) {
        return strpos(strtolower($f['name']), $q) !== false;
    });
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Manager</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-body: #f8fafc;
            --bg-sidebar: #ffffff;
            --bg-header: #ffffff;
            --bg-card: #ffffff;
            --border-soft: #e2e8f0;
            --primary: #3b82f6;
            --primary-soft: #dbeafe;
            --primary-dark: #2563eb;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #06b6d4;
            --radius-lg: 12px;
            --radius-md: 8px;
            --radius-sm: 6px;
            --shadow-soft: 0 4px 12px rgba(15, 23, 42, 0.08);
            --shadow-medium: 0 10px 25px rgba(15, 23, 42, 0.1);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Poppins', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-body);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            line-height: 1.6;
        }

        /* SIDEBAR */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100vh;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border-soft);
            padding: 20px 16px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            z-index: 1000;
            overflow-y: auto;
            transition: transform 0.3s ease;
        }
        .sidebar.open {
            transform: translateX(0);
        }
        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding: 0 8px;
        }
        .brand-logo {
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 18px;
            box-shadow: var(--shadow-soft);
        }
        .brand-text { display: flex; flex-direction: column; }
        .brand-title { font-size: 17px; font-weight: 700; color: var(--text-main); }
        .brand-subtitle { font-size: 11px; color: var(--text-muted); margin-top: -2px; }

        .sidebar ul {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .sidebar li { width: 100%; }
        .sidebar a {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            border-radius: var(--radius-md);
            text-decoration: none;
            color: var(--text-muted);
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
            position: relative;
        }
        .nav-icon { width: 20px; text-align: center; font-size: 16px; }
        .sidebar a:hover {
            background: #f1f5f9;
            color: var(--primary-dark);
            transform: translateX(2px);
        }
        .sidebar a.active {
            background: var(--primary-soft);
            color: var(--primary-dark);
            font-weight: 600;
            box-shadow: var(--shadow-soft);
        }

        /* MAIN CONTENT */
        .main-content {
            margin-left: 260px;
            flex: 1;
            min-height: 100vh;
            padding: 24px 28px 32px;
        }
        .page-container {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* HEADER */
        .header {
            background: var(--bg-header);
            border-radius: var(--radius-lg);
            padding: 20px 24px;
            border: 1px solid var(--border-soft);
            box-shadow: var(--shadow-soft);
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .header-left { display: flex; flex-direction: column; gap: 6px; }
        .page-title { font-size: 24px; font-weight: 700; color: var(--text-main); }
        .page-subtitle { font-size: 14px; color: var(--text-muted); }
        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }
        .chip {
            font-size: 12px;
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid var(--border-soft);
            color: var(--text-muted);
            background: #f8fafc;
            font-weight: 500;
        }
        .chip-live {
            border-color: rgba(16, 185, 129, 0.3);
            color: var(--success);
            background: #ecfdf5;
        }
        .user-info { 
            display: flex; 
            align-items: center; 
            gap: 12px; 
            padding: 8px 12px;
            background: #f8fafc;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-soft);
        }
        .user-avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-soft);
        }
        .user-meta { display: flex; flex-direction: column; }
        .user-name { font-size: 14px; font-weight: 600; }
        .user-role { font-size: 12px; color: var(--text-muted); }

        /* ALERTS */
        .alert {
            border-radius: var(--radius-md);
            padding: 14px 16px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-left: 4px solid transparent;
        }
        .alert-success {
            background: #ecfdf5;
            border-color: var(--success);
            color: #065f46;
        }
        .alert-error {
            background: #fef2f2;
            border-color: var(--danger);
            color: #991b1b;
        }

        .card {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-soft);
            border: 1px solid var(--border-soft);
            margin-bottom: 20px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .card-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-soft);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-title { font-size: 16px; font-weight: 600; color: var(--text-main); }
        .card-subtitle { font-size: 13px; color: var(--text-muted); margin-top: 2px; }
        .card-body { padding: 16px 20px; }

        /* ToolBar & breadcrumb */
        .file-toolbar {
            display: flex;
            flex-direction: column;
            gap: 16px;
            margin-bottom: 20px;
        }
        .breadcrumb {
            font-size: 14px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            flex: 1;
            min-width: 200px;
        }
        .breadcrumb a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s ease;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .breadcrumb a:hover { color: var(--primary-dark); text-decoration: underline; }
        .breadcrumb-separator { color: var(--text-muted); font-size: 12px; }

        .toolbar-row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 12px;
        }
        .toolbar-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        .toolbar-actions { display: flex; align-items: center; }

        .btn {
            padding: 10px 18px;
            border-radius: var(--radius-md);
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-soft);
        }
        .btn-primary { background: var(--primary); color: #ffffff; }
        .btn-primary:hover { background: var(--primary-dark); transform: translateY(-2px); }
        .btn-secondary { background: #f8fafc; color: var(--text-main); border: 1px solid var(--border-soft); }
        .btn-secondary:hover { background: #f1f5f9; transform: translateY(-2px); box-shadow: var(--shadow-medium); }
        .btn-success { background: var(--success); color: white; }
        .btn-success:hover { background: #059669; transform: translateY(-2px); }
        .btn-warning { background: var(--warning); color: white; }
        .btn-warning:hover { background: #d97706; transform: translateY(-2px); }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover { background: #dc2626; transform: translateY(-2px); }

        .action-btn {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 8px 12px;
            background: white;
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-md);
            color: var(--text-main);
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .action-btn:hover {
            background: var(--primary-soft);
            border-color: var(--primary);
            color: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: var(--shadow-soft);
        }
        .action-buttons { display: flex; gap: 8px; flex-wrap: wrap; }

        .search-box {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 16px;
            border-radius: var(--radius-md);
            background: #f8fafc;
            border: 1px solid var(--border-soft);
            transition: all 0.2s ease;
        }
        .search-box:focus-within {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        .search-box input {
            border: none;
            outline: none;
            background: transparent;
            font-size: 14px;
            width: 200px;
            color: var(--text-main);
        }
        .select-sort {
            border-radius: var(--radius-md);
            border: 1px solid var(--border-soft);
            background: #ffffff;
            padding: 10px 16px;
            font-size: 14px;
            color: var(--text-main);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        /* File list - Table View */
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }
        .file-table th {
            background: #f8fafc;
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
            color: var(--text-muted);
            font-size: 13px;
            border-bottom: 1px solid var(--border-soft);
        }
        .file-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-soft);
            font-size: 14px;
        }
        .file-table tr.selected-row { background-color: var(--primary-soft); }
        .file-table tr:not(.selected-row):hover { background: #f8fafc; }
        .file-table .file-icon { width: 20px; text-align: center; margin-right: 8px; }
        .file-table input[type="checkbox"] { cursor: pointer; width: 16px; height: 16px; }

        /* File actions */
        .file-actions { display: flex; gap: 6px; justify-content: flex-end; }
        .btn-sm { padding: 6px 10px; font-size: 12px; }
        .btn-icon {
            padding: 8px;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--radius-sm);
        }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #e2e8f0; color: #475569; }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.6);
            z-index: 2000;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(4px);
        }
        .modal-content {
            background: white;
            border-radius: var(--radius-lg);
            padding: 24px;
            max-width: 500px;
            width: 90%;
            box-shadow: var(--shadow-medium);
            transform: scale(0.9);
            opacity: 0;
            animation: modalOpen 0.3s ease forwards;
        }
        @keyframes modalOpen { to { transform: scale(1); opacity: 1; } }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-title { font-size: 18px; font-weight: 700; color: var(--text-main); }
        .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-muted); }
        .modal-close:hover { color: var(--danger); }
        .modal-body { margin-bottom: 24px; }
        .modal-footer { display: flex; gap: 12px; justify-content: flex-end; }
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; margin-bottom: 6px; font-weight: 600; color: var(--text-main); font-size: 14px; }
        .form-input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-md);
            font-size: 14px;
            transition: all 0.2s ease;
        }
        .form-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); outline: none; }
        
        /* Drag Drop */
        .upload-dropzone {
            border: 2px dashed #cbd5e1;
            background: #f8fafc;
            border-radius: var(--radius-md);
            padding: 40px 20px;
            text-align: center;
            font-size: 14px;
            color: var(--text-muted);
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .upload-dropzone.dragover { border-color: var(--primary); background: #eff6ff; transform: scale(1.02); }
        .upload-dropzone i { font-size: 48px; margin-bottom: 16px; color: var(--primary); }
        .upload-progress { margin-top: 16px; display: none; }
        .progress-bar { width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--success); width: 0%; transition: width 0.3s ease; }
        .upload-status-text { font-size: 13px; font-weight: 500; margin-bottom: 8px; color: var(--text-muted); }

        /* Path Selector */
        .path-selector {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-md);
            padding: 8px;
        }
        .path-option {
            padding: 8px 12px;
            cursor: pointer;
            border-radius: var(--radius-sm);
            transition: background 0.2s ease;
            font-size: 14px;
        }
        .path-option:hover { background: #f1f5f9; }
        .path-option.selected { background: var(--primary-soft); color: var(--primary-dark); font-weight: 600; }

        /* Context Menu */
        .context-menu {
            position: fixed;
            background: white;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-medium);
            border: 1px solid var(--border-soft);
            z-index: 3000;
            min-width: 200px;
            display: none;
            padding: 6px;
        }
        .context-menu-item {
            padding: 10px 16px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s ease;
            border-radius: var(--radius-sm);
        }
        .context-menu-item:hover { background: var(--primary-soft); color: var(--primary-dark); }
        .context-menu-item.divider { border-bottom: 1px solid var(--border-soft); margin: 4px 0; padding: 0; }
        .context-menu-item.danger { color: var(--danger); }
        .context-menu-item.danger:hover { background: #fef2f2; color: #dc2626; }

        /* Selection Toolbar */
        .selection-toolbar {
            position: fixed;
            bottom: -100px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--text-main);
            color: white;
            border-radius: var(--radius-lg);
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: var(--shadow-medium);
            z-index: 1500;
            transition: bottom 0.3s ease-in-out;
        }
        .selection-toolbar.visible { bottom: 24px; }
        .selection-count { font-weight: 600; font-size: 14px; }
        .selection-actions { display: flex; gap: 10px; }
        .selection-actions button {
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 8px 14px;
            font-size: 13px;
        }
        .selection-actions button:hover { background: rgba(255, 255, 255, 0.2); }
        .selection-actions button.danger { background: rgba(239, 68, 68, 0.2); border-color: rgba(239, 68, 68, 0.4); }
        .selection-actions button.danger:hover { background: var(--danger); border-color: var(--danger); }

        /* Responsive */
        .mobile-menu-btn {
            display: none;
            position: fixed;
            top: 16px;
            left: 16px;
            z-index: 1001;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: var(--radius-md);
            padding: 10px;
            cursor: pointer;
            box-shadow: var(--shadow-medium);
        }
        @media (max-width: 1024px) {
            .file-layout { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); }
            .main-content { margin-left: 0; padding: 16px; }
            .mobile-menu-btn { display: block; }
            .header { flex-direction: column; align-items: flex-start; }
            .header-right { justify-content: space-between; width: 100%; }
        }
    </style>
</head>
<body>

    <!-- Mobile Menu Button -->
    <button class="mobile-menu-btn" id="mobileMenuBtn">
        <i class="fas fa-bars"></i>
    </button>

    <!-- SIDEBAR -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-brand">
            <div class="brand-logo">FM</div>
            <div class="brand-text">
                <div class="brand-title">FileManager</div>
                <div class="brand-subtitle">Secure & Simple</div>
            </div>
        </div>

        <ul>
            <li>
                <a href="index.php?path=%2F" class="active">
                    <span class="nav-icon"><i class="fas fa-folder-open"></i></span>
                    <span>Files</span>
                </a>
            </li>
            <li>
                <a href="#" onclick="refreshPage()">
                    <span class="nav-icon"><i class="fas fa-sync-alt"></i></span>
                    <span>Refresh</span>
                </a>
            </li>
        </ul>

        <div style="margin-top: auto; padding: 16px 8px 0; border-top: 1px solid var(--border-soft); font-size: 11px; color: var(--text-muted);">
            <span>Host: <?php echo $_SERVER['SERVER_NAME']; ?></span>
            <span>IP: <?php echo $_SERVER['SERVER_ADDR']; ?></span>
        </div>
    </div>

    <!-- MAIN -->
    <main class="main-content">
        <div class="page-container">
            <!-- HEADER -->
            <section class="header">
                <div class="header-left">
                    <div class="page-title">File Management</div>
                    <div class="page-subtitle">
                        <?php echo htmlspecialchars($root_path); ?>
                    </div>
                </div>
                <div class="header-right">
                    <span class="chip chip-live">
                        <i class="fas fa-circle"></i> Connected
                    </span>
                    <div class="user-info">
                        <div class="user-avatar">
                            <?php 
                                $u = isset($_SESSION['admin_user']) ? 'Admin' : ($_SESSION['client_user'] ?? 'U');
                                echo strtoupper(substr($u, 0, 1)); 
                            ?>
                        </div>
                        <div class="user-meta">
                            <span class="user-name"><?php echo htmlspecialchars($u); ?></span>
                            <span class="user-role"><?php echo isset($_SESSION['admin_user']) ? 'Administrator' : 'Client User'; ?></span>
                        </div>
                    </div>
                </div>
            </section>

            <!-- ALERTS -->
            <?php if (isset($_GET['success'])): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($_GET['success']); ?>
                </div>
            <?php endif; ?>
            <?php if (isset($_GET['error'])): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($_GET['error']); ?>
                </div>
            <?php endif; ?>

            <!-- Toolbar & Breadcrumb -->
            <div class="file-toolbar">
                <div class="toolbar-content">
                    <a class="action-btn" href="index.php?path=<?php echo urlencode(dirname($current_path)); ?>" title="Go Up">
                        <i class="fas fa-level-up-alt"></i>
                        <span>Up</span>
                    </a>
                    <div class="breadcrumb">
                        <a href="index.php?path=%2F">
                            <i class="fas fa-home"></i> Root
                        </a>
                        <?php
                        $parts = explode('/', trim($current_path, '/'));
                        $crumb = '/';
                        foreach ($parts as $part) {
                            if ($part === '') continue;
                            $crumb .= $part . '/';
                            echo '<span class="breadcrumb-separator"><i class="fas fa-chevron-right"></i></span>';
                            echo '<a href="index.php?path=' . urlencode($crumb) . '">' . htmlspecialchars($part) . '</a>';
                        }
                        ?>
                    </div>

                    <div class="toolbar-actions">
                        <div class="action-buttons">
                            <button class="action-btn" onclick="showUploadModal()" title="Upload Files">
                                <i class="fas fa-upload"></i>
                                <span>Upload</span>
                            </button>
                            
                            <button class="action-btn" onclick="showCreateFileModal()" title="New File">
                                <i class="fas fa-plus"></i>
                                <span>File</span>
                            </button>
                            
                            <button class="action-btn" onclick="showCreateFolderModal()" title="New Folder">
                                <i class="fas fa-folder-plus"></i>
                                <span>Folder</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- File list -->
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">
                            <i class="fas fa-folder-open"></i> 
                            <?php echo $current_path === '/' ? 'Root Directory' : htmlspecialchars(basename($current_path)); ?>
                        </div>
                        <div class="card-subtitle">
                            <?php echo count($files); ?> items
                            <?php if ($search_query): ?>
                                • Searching for "<?php echo htmlspecialchars($search_query); ?>"
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="toolbar-row">
                        <form method="get" class="toolbar-row" style="flex: 1;">
                            <input type="hidden" name="path" value="<?php echo htmlspecialchars($current_path); ?>">
                            
                            <div class="search-box">
                                <i class="fas fa-search"></i>
                                <input type="text" name="q" placeholder="Search..." value="<?php echo htmlspecialchars($search_query); ?>">
                            </div>

                            <select name="sort" class="select-sort" onchange="this.form.submit()">
                                <option value="name" <?php echo $sort === 'name' ? 'selected' : ''; ?>>Sort by Name</option>
                                <option value="size" <?php echo $sort === 'size' ? 'selected' : ''; ?>>Sort by Size</option>
                                <option value="modified" <?php echo $sort === 'modified' ? 'selected' : ''; ?>>Sort by Modified</option>
                            </select>
                        </form>
                    </div>
                </div>
                <div class="card-body">
                    <?php if (empty($files)): ?>
                        <div style="text-align: center; padding: 40px 20px;">
                            <i class="fas fa-folder-open" style="font-size: 48px; color: var(--border-soft); margin-bottom: 16px;"></i>
                            <p style="font-size: 16px; color: var(--text-muted); margin-bottom: 8px;">
                                This folder is empty
                            </p>
                            <p style="font-size: 14px; color: var(--text-muted);">
                                Upload files or create new folders to get started.
                            </p>
                        </div>
                    <?php else: ?>
                        <table class="file-table">
                            <thead>
                                <tr>
                                    <th style="width: 1%; padding-left: 10px;"><input type="checkbox" id="selectAllCheckbox"></th>
                                    <th>Name</th>
                                    <th>Size</th>
                                    <th>Permissions</th>
                                    <th>Modified</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($files as $f): ?>
                                    <?php
                                    $isDir = $f['is_dir'];
                                    $rel   = $f['relative'];
                                    $name  = $f['name'];

                                    $fa_icon = 'fa-file';
                                    $color = '#6b7280';
                                    if ($isDir) {
                                        $fa_icon = 'fa-folder';
                                        $color = '#f59e0b';
                                    } elseif (in_array($f['extension'], ['jpg','jpeg','png','gif','webp'])) {
                                        $fa_icon = 'fa-file-image';
                                        $color = '#10b981';
                                    } elseif (in_array($f['extension'], ['zip','tar','gz','rar'])) {
                                        $fa_icon = 'fa-file-archive';
                                        $color = '#f97316';
                                    } elseif (in_array($f['extension'], ['php','html','css','js'])) {
                                        $fa_icon = 'fa-file-code';
                                        $color = '#3b82f6';
                                    }
                                    ?>
                                    <tr ondblclick="<?php echo $isDir ? 'window.location=\'index.php?path=' . urlencode($rel . '/') . '\'' : 'window.open(\'editor.php?file=' . urlencode($rel) . '\', \'_blank\')'; ?>"
                                        oncontextmenu="showContextMenu(event, '<?php echo htmlspecialchars(addslashes($rel)); ?>', '<?php echo htmlspecialchars(addslashes($name)); ?>', '<?php echo $isDir ? 'dir' : 'file'; ?>')">
                                        <td style="padding-left: 10px;">
                                            <input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($rel); ?>">
                                        </td>
                                        <td>
                                            <i class="fas <?php echo $fa_icon; ?> file-icon" style="color: <?php echo $color; ?>"></i>
                                            <?php if ($isDir): ?>
                                                <a href="index.php?path=<?php echo urlencode($rel . '/'); ?>" style="text-decoration: none; color: inherit; font-weight: 600;">
                                                    <?php echo htmlspecialchars($name); ?>
                                                </a>
                                            <?php else: ?>
                                                <span style="font-weight: 500;"><?php echo htmlspecialchars($name); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo $isDir ? '-' : format_file_size($f['size']); ?></td>
                                        <td>
                                            <span class="badge"><?php echo htmlspecialchars($f['permissions']); ?></span>
                                        </td>
                                        <td><?php echo htmlspecialchars($f['modified']); ?></td>
                                        <td>
                                            <div class="file-actions">
                                                <button class="btn btn-icon btn-sm" 
                                                        onclick="downloadItem('<?php echo htmlspecialchars(addslashes($rel)); ?>')"
                                                        title="Download">
                                                    <i class="fas fa-download"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>

    <!-- Hidden Forms -->
    <form id="permissionsForm" method="post" style="display:none;"></form>
    <form id="deleteForm" method="post" style="display:none;"></form>
    <form id="renameForm" method="post" style="display:none;"></form>
    <form id="copyForm" method="post" style="display:none;"></form>
    <form id="moveForm" method="post" style="display:none;"></form>
    <form id="zipForm" method="post" style="display:none;"></form>
    <form id="unzipForm" method="post" style="display:none;"></form>
    <form id="downloadForm" method="post" style="display:none;"></form>
    
    <form id="zipSelectedForm" method="post" style="display:none;"></form>
    <form id="deleteSelectedForm" method="post" style="display:none;"></form>
    <form id="copySelectedForm" method="post" style="display:none;"></form>
    <form id="moveSelectedForm" method="post" style="display:none;"></form>

    <!-- Generic Modal -->
    <div class="modal" id="actionModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title" id="modalTitle">Action</div>
                <button class="modal-close" onclick="closeModal('actionModal')">&times;</button>
            </div>
            <div class="modal-body" id="modalBody"></div>
            <div class="modal-footer" id="modalFooter"></div>
        </div>
    </div>

    <!-- Path Selector Modal -->
    <div class="modal" id="pathModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title" id="pathModalTitle">Select Destination</div>
                <button class="modal-close" onclick="closeModal('pathModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label" id="pathModalLabel">Choose destination folder:</label>
                    <div class="path-selector" id="pathSelector"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('pathModal')">Cancel</button>
                <button class="btn btn-primary" id="confirmPathBtn" onclick="confirmPathSelection()">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Context Menu -->
    <div class="context-menu" id="contextMenu"></div>

    <!-- Selection Toolbar -->
    <div class="selection-toolbar" id="selectionToolbar">
        <div class="selection-count" id="selectionCount">0 items selected</div>
        <div class="selection-actions">
            <button class="btn btn-sm" onclick="copySelected()"><i class="fas fa-copy"></i> Copy</button>
            <button class="btn btn-sm" onclick="moveSelected()"><i class="fas fa-cut"></i> Move</button>
            <button class="btn btn-sm" onclick="zipSelected()"><i class="fas fa-file-archive"></i> Zip</button>
            <button class="btn btn-sm danger" onclick="deleteSelected()"><i class="fas fa-trash"></i> Delete</button>
        </div>
    </div>

    <script>
        // State
        let contextMenuFilePath = '';
        let contextMenuFileName = '';
        let contextMenuFileType = '';

        document.getElementById('mobileMenuBtn').addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });
        
        function refreshPage() {
            window.location.reload(true);
        }

        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            if(modal) modal.style.display = 'flex';
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if(modal) modal.style.display = 'none';
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeModal('actionModal');
                closeModal('pathModal');
                closeContextMenu();
            }
        });

        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                closeModal(event.target.id);
            }
        }

        // --- UPLOAD ---
        function showUploadModal() {
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = '<i class="fas fa-upload"></i> Upload Files';
            modalBody.innerHTML = `
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                    Maximum file size: 500MB. Drag and drop or click to select files.
                </p>
                <div class="upload-dropzone" id="dropzone" onclick="document.getElementById('file-input-ajax').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <div>Drag & drop files here or click to browse</div>
                </div>
                <input type="file" id="file-input-ajax" style="display: none;" multiple>
                <div class="upload-progress" id="uploadProgress">
                    <div class="upload-status-text" id="uploadStatusText">Starting upload...</div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                </div>
            `;
            modalFooter.innerHTML = `<button class="btn btn-secondary" onclick="closeModal('actionModal')">Close</button>`;
            
            showModal('actionModal');

            const dropzone = document.getElementById('dropzone');
            const fileInput = document.getElementById('file-input-ajax');

            dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
            dropzone.addEventListener('dragleave', e => { e.preventDefault(); dropzone.classList.remove('dragover'); });
            dropzone.addEventListener('drop', e => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
                if (e.dataTransfer.files.length > 0) handleFileUpload(e.dataTransfer.files);
            });
            fileInput.addEventListener('change', e => {
                if(e.target.files.length > 0) handleFileUpload(e.target.files);
            });
        }
        
        function handleFileUpload(files) {
            const progressContainer = document.getElementById('uploadProgress');
            const progressFill = document.getElementById('progressFill');
            const statusText = document.getElementById('uploadStatusText');

            progressContainer.style.display = 'block';
            statusText.textContent = `Uploading ${files.length} file(s)...`;

            const formData = new FormData();
            formData.append('upload_files', '1');
            for (const file of files) {
                formData.append('files[]', file);
            }

            const xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.href, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

            xhr.upload.onprogress = function(e) {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete.toFixed(2) + '%';
                    statusText.textContent = `Uploading... ${percentComplete.toFixed(0)}%`;
                }
            };

            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.success) {
                            statusText.textContent = 'Upload complete! Refreshing...';
                            progressFill.style.background = 'var(--success)';
                            setTimeout(() => { closeModal('actionModal'); refreshPage(); }, 1000);
                        } else {
                            statusText.innerHTML = `Upload failed: ${response.message || 'Server error'}`;
                            progressFill.style.background = 'var(--danger)';
                        }
                    } catch(e) {
                        statusText.innerHTML = `Upload failed: Invalid response.`;
                        progressFill.style.background = 'var(--danger)';
                    }
                } else {
                    statusText.textContent = `Upload failed status: ${xhr.status}`;
                    progressFill.style.background = 'var(--danger)';
                }
            };
            
            xhr.onerror = function() {
                statusText.textContent = 'Network error.';
                progressFill.style.background = 'var(--danger)';
            };

            xhr.send(formData);
        }

        // --- CREATE FILES/FOLDERS ---
        function showCreateFolderModal() {
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = '<i class="fas fa-folder-plus"></i> Create New Folder';
            modalBody.innerHTML = `
                <form id="createFolderForm" method="post">
                    <input type="hidden" name="create_folder" value="1">
                    <div class="form-group">
                        <label for="folder_name" class="form-label">Folder Name</label>
                        <input type="text" id="folder_name" name="folder_name" class="form-input" required placeholder="Enter folder name">
                    </div>
                </form>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-success" onclick="document.getElementById('createFolderForm').submit()">Create</button>`;
            
            showModal('actionModal');
            document.getElementById('folder_name').focus();
        }
        
        function showCreateFileModal() {
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = '<i class="fas fa-file-plus"></i> Create New File';
            modalBody.innerHTML = `
                <form id="createFileForm" method="post">
                    <input type="hidden" name="create_file" value="1">
                    <div class="form-group">
                        <label for="file_name" class="form-label">File Name</label>
                        <input type="text" id="file_name" name="file_name" class="form-input" required placeholder="Enter file name">
                    </div>
                </form>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-warning" onclick="document.getElementById('createFileForm').submit()">Create</button>`;
            
            showModal('actionModal');
            document.getElementById('file_name').focus();
        }

        // --- CONTEXT MENU ---
        function showContextMenu(event, filePath, fileName, fileType) {
            event.preventDefault();
            closeContextMenu();

            contextMenuFilePath = filePath;
            contextMenuFileName = fileName;
            contextMenuFileType = fileType;
            
            const contextMenu = document.getElementById('contextMenu');
            const isZip = fileType === 'file' && fileName.endsWith('.zip');
            
            contextMenu.innerHTML = `
                <div class="context-menu-item" onclick="contextMenuDownload()"><i class="fas fa-download"></i> Download</div>
                <div class="context-menu-item" onclick="contextMenuRename()"><i class="fas fa-edit"></i> Rename</div>
                <div class="context-menu-item" onclick="contextMenuCopy()"><i class="fas fa-copy"></i> Copy</div>
                <div class="context-menu-item" onclick="contextMenuMove()"><i class="fas fa-cut"></i> Move</div>
                <div class="context-menu-item" onclick="contextMenuPermissions()"><i class="fas fa-lock"></i> Permissions</div>
                <div class="context-menu-item divider"></div>
                <div class="context-menu-item" onclick="contextMenuZip()"><i class="fas fa-file-archive"></i> Create Zip</div>
                ${isZip ? `<div class="context-menu-item" onclick="contextMenuUnzip()"><i class="fas fa-expand-arrows-alt"></i> Extract Zip</div>` : ''}
                <div class="context-menu-item divider"></div>
                <div class="context-menu-item danger" onclick="contextMenuDelete()"><i class="fas fa-trash"></i> Delete</div>
            `;
            
            contextMenu.style.display = 'block';
            
            const { clientX: mouseX, clientY: mouseY } = event;
            const { innerWidth, innerHeight } = window;
            const menuWidth = contextMenu.offsetWidth;
            const menuHeight = contextMenu.offsetHeight;

            const posX = mouseX + menuWidth > innerWidth ? innerWidth - menuWidth - 5 : mouseX;
            const posY = mouseY + menuHeight > innerHeight ? innerHeight - menuHeight - 5 : mouseY;
            
            contextMenu.style.left = `${posX}px`;
            contextMenu.style.top = `${posY}px`;
            
            setTimeout(() => document.addEventListener('click', closeContextMenu, { once: true }), 0);
        }

        function closeContextMenu() {
            const contextMenu = document.getElementById('contextMenu');
            if(contextMenu) contextMenu.style.display = 'none';
        }

        function contextMenuDownload() { downloadItem(contextMenuFilePath); }
        function contextMenuZip() { zipItem(contextMenuFilePath); }
        function contextMenuUnzip() { unzipItem(contextMenuFilePath); }
        function contextMenuRename() {
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = `<i class="fas fa-edit"></i> Rename Item`;
            modalBody.innerHTML = `
                <p>Renaming: <strong>${contextMenuFileName}</strong></p>
                <form id="renameFormModal" method="post">
                    <input type="hidden" name="rename_path" value="1">
                    <input type="hidden" name="file_path" value="${contextMenuFilePath}">
                    <div class="form-group" style="margin-top: 16px;">
                        <label for="new_name" class="form-label">New Name</label>
                        <input type="text" id="new_name" name="new_name" class="form-input" required value="${contextMenuFileName}">
                    </div>
                </form>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-primary" onclick="document.getElementById('renameFormModal').submit()">Save</button>`;
            
            showModal('actionModal');
            document.getElementById('new_name').focus();
        }

        function contextMenuDelete() {
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = `<i class="fas fa-trash"></i> Confirm Deletion`;
            modalBody.innerHTML = `<p>Permanently delete <strong>${contextMenuFileName}</strong>?</p>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-danger" onclick="deleteItem('${contextMenuFilePath}')">Delete</button>`;
            showModal('actionModal');
        }

        function contextMenuPermissions() {
             const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = `<i class="fas fa-lock"></i> Change Permissions`;
            modalBody.innerHTML = `
                <p>Editing: <strong>${contextMenuFileName}</strong></p>
                <form id="permissionsFormModal" method="post">
                    <input type="hidden" name="change_permissions" value="1">
                    <input type="hidden" name="file_path" value="${contextMenuFilePath}">
                    <div class="form-group" style="margin-top: 16px;">
                        <label for="permissions" class="form-label">Permissions (e.g., 755)</label>
                        <input type="text" id="permissions" name="permissions" class="form-input" required pattern="[0-7]{3,4}" value="0644">
                    </div>
                </form>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-primary" onclick="document.getElementById('permissionsFormModal').submit()">Update</button>`;
            
            showModal('actionModal');
            document.getElementById('permissions').focus();
        }

        function contextMenuCopy() { showPathSelector('copy', contextMenuFilePath, contextMenuFileName); }
        function contextMenuMove() { showPathSelector('move', contextMenuFilePath, contextMenuFileName); }

        // --- CORE ACTIONS ---
        function submitSingleItemForm(formId, filePath) {
            const form = document.getElementById(formId);
            form.innerHTML = ''; 
            
            const pathInput = document.createElement('input');
            pathInput.type = 'hidden';
            pathInput.name = formId.replace('Form', '_path');
            pathInput.value = '1';
            form.appendChild(pathInput);

            const valueInput = document.createElement('input');
            valueInput.type = 'hidden';
            valueInput.name = 'file_path';
            valueInput.value = filePath;
            form.appendChild(valueInput);

            form.submit();
        }
        function deleteItem(filePath) { submitSingleItemForm('deleteForm', filePath); }
        function zipItem(filePath) { submitSingleItemForm('zipForm', filePath); }
        function unzipItem(filePath) { submitSingleItemForm('unzipForm', filePath); }
        function downloadItem(filePath) { submitSingleItemForm('downloadForm', filePath); }

        // --- PATH SELECTOR ---
        let currentPathAction = '';
        let currentActionFilePath = '';
        let currentSelectedPath = '/';

        function showPathSelector(action, filePath, fileName) {
            currentPathAction = action;
            currentActionFilePath = filePath;
            
            const title = document.getElementById('pathModalTitle');
            const label = document.getElementById('pathModalLabel');
            const selector = document.getElementById('pathSelector');
            const selectedCount = document.querySelectorAll('.file-checkbox:checked').length;
            
            const actionText = action.includes('copy') ? 'Copy' : 'Move';
            const itemCountText = action.includes('selected') ? `${selectedCount} items` : `"${fileName}"`;

            title.textContent = `${actionText} ${itemCountText}`;
            
            selector.innerHTML = `<div class="path-option" onclick="selectPath(this, '/')"><i class="fas fa-folder" style="margin-right: 8px;"></i> / (Root)</div>`;
            selector.innerHTML += generateDirectoryTree(<?php echo json_encode($directory_tree); ?>);
            
            showModal('pathModal');
        }

        function generateDirectoryTree(tree, level = 0) {
            let html = '';
            tree.forEach(item => {
                const padding = (level + 1) * 20;
                html += `<div class="path-option" onclick="selectPath(this, '${item.path}')" style="padding-left: ${padding}px;"><i class="fas fa-folder" style="margin-right: 8px;"></i> ${item.name}</div>`;
                if (item.children && item.children.length > 0) {
                    html += generateDirectoryTree(item.children, level + 1);
                }
            });
            return html;
        }

        function selectPath(element, path) {
            document.querySelectorAll('.path-option').forEach(opt => opt.classList.remove('selected'));
            element.classList.add('selected');
            currentSelectedPath = path;
        }

        function confirmPathSelection() {
            let form;
            if (currentPathAction === 'copy_selected' || currentPathAction === 'move_selected') {
                const action = currentPathAction.split('_')[0];
                form = document.getElementById(`${action}SelectedForm`);
                populateMultiSelectForm(form, currentPathAction, 'target_path', currentSelectedPath);
            } else {
                form = document.getElementById(currentPathAction + 'Form');
                form.file_path.value = currentActionFilePath;
                form.target_path.value = currentSelectedPath;
            }
            form.submit();
        }

        // --- MULTI-SELECT ---
        function getSelectedPaths() {
            return Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
        }

        function populateMultiSelectForm(form, action, ...additionalFields) {
            form.innerHTML = '';
            
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = action;
            actionInput.value = '1';
            form.appendChild(actionInput);
            
            for (let i = 0; i < additionalFields.length; i += 2) {
                const name = additionalFields[i];
                const value = additionalFields[i+1];
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = name;
                input.value = value;
                form.appendChild(input);
            }
            
            getSelectedPaths().forEach(path => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'selected_paths[]';
                input.value = path;
                form.appendChild(input);
            });
        }

        function copySelected() { showPathSelector('copy_selected'); }
        function moveSelected() { showPathSelector('move_selected'); }
        
        function deleteSelected() {
            const selectedCount = getSelectedPaths().length;
            if (selectedCount === 0) return;

            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = `<i class="fas fa-trash"></i> Confirm Deletion`;
            modalBody.innerHTML = `<p>Permanently delete ${selectedCount} selected item(s)?</p>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-danger" onclick="submitDeleteSelectedForm()">Delete All</button>`;
            
            showModal('actionModal');
        }

        function submitDeleteSelectedForm() {
            const form = document.getElementById('deleteSelectedForm');
            populateMultiSelectForm(form, 'delete_selected');
            form.submit();
        }
        
        function zipSelected() {
            const selectedCount = getSelectedPaths().length;
            if (selectedCount === 0) return;

            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalFooter = document.getElementById('modalFooter');

            modalTitle.innerHTML = `<i class="fas fa-file-archive"></i> Create Zip Archive`;
            modalBody.innerHTML = `
                <p>Creating archive from ${selectedCount} items.</p>
                <div class="form-group" style="margin-top: 16px;">
                    <label for="zip_name" class="form-label">Archive Name</label>
                    <input type="text" id="zip_name" name="zip_name" class="form-input" required value="archive.zip">
                </div>`;
            modalFooter.innerHTML = `
                <button class="btn btn-secondary" onclick="closeModal('actionModal')">Cancel</button>
                <button class="btn btn-primary" onclick="submitZipSelectedForm()">Create</button>`;
            
            showModal('actionModal');
            document.getElementById('zip_name').focus();
        }

        function submitZipSelectedForm() {
            const form = document.getElementById('zipSelectedForm');
            const zipName = document.getElementById('zip_name').value;
            populateMultiSelectForm(form, 'zip_selected', 'zip_name', zipName);
            form.submit();
        }

        document.addEventListener('DOMContentLoaded', () => {
            const selectAllCheckbox = document.getElementById('selectAllCheckbox');
            const fileCheckboxes = document.querySelectorAll('.file-checkbox');

            const toggleRowHighlight = (checkbox) => {
                const row = checkbox.closest('tr');
                if (checkbox.checked) {
                    row.classList.add('selected-row');
                } else {
                    row.classList.remove('selected-row');
                }
            };

            selectAllCheckbox.addEventListener('change', (e) => {
                fileCheckboxes.forEach(checkbox => {
                    checkbox.checked = e.target.checked;
                    toggleRowHighlight(checkbox);
                });
                updateSelectionToolbar();
            });

            fileCheckboxes.forEach(checkbox => {
                checkbox.addEventListener('change', () => {
                    toggleRowHighlight(checkbox);
                    if (!checkbox.checked) {
                        selectAllCheckbox.checked = false;
                    }
                    updateSelectionToolbar();
                });
            });
        });

        function updateSelectionToolbar() {
            const count = document.querySelectorAll('.file-checkbox:checked').length;
            const toolbar = document.getElementById('selectionToolbar');
            const countDisplay = document.getElementById('selectionCount');

            if (count > 0) {
                countDisplay.textContent = `${count} item${count > 1 ? 's' : ''} selected`;
                toolbar.classList.add('visible');
            } else {
                toolbar.classList.remove('visible');
            }
        }
    </script>
</body>
</html>
