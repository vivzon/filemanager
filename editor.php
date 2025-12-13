<?php
// pages/editor.php
session_start();

// 1. Security Check & Root Path Configuration
// (Matches index.php logic exactly)
if (!isset($_SESSION["client_user"]) && !isset($_SESSION["admin_user"])) {
    die("Access Denied: Please log in.");
}

// Define Root Path based on session
if (isset($_SESSION["admin_user"])) {
    $root_path = "/var/www/clients";
    $user_label = "Administrator";
} else {
    $cuser = $_SESSION["client_user"];
    $root_path = "/var/www/clients/$cuser";
    $user_label = $cuser;
}

// 2. Helpers (Security & Paths)
function shm_normalize_path($path) {
    $path = str_replace('\\', '/', $path);
    $path = '/' . ltrim($path, '/');
    $parts = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') continue;
        if ($part === '..') array_pop($parts);
        else $parts[] = $part;
    }
    return '/' . implode('/', $parts);
}

function shm_build_safe_path($base, $relative) {
    $base = rtrim(str_replace('\\', '/', $base), '/');
    $relative = shm_normalize_path($relative);
    $full = $base . $relative;
    
    // Security check: ensure path is inside base
    // Also checks if file actually exists to resolve realpath symlinks if needed
    if (file_exists($full)) {
        $real = realpath($full);
        if ($real === false || strpos($real, $base) !== 0) {
            return false;
        }
        return $real;
    }
    
    // If it doesn't exist (shouldn't happen in editor), check string path
    if (strpos($full, $base) !== 0) return false;
    return $full;
}

// 3. Inputs
$file_rel = isset($_GET['file']) ? $_GET['file'] : '';

// 4. Validation & Path Building
if (empty($file_rel)) {
    die("Invalid parameters: No file specified.");
}

$file_path = shm_build_safe_path($root_path, $file_rel);

if (!$file_path || !file_exists($file_path)) {
    die("File not found or access denied: " . htmlspecialchars($file_rel));
}

// 5. Handle AJAX Save (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    // Read input stream for raw content
    $content = file_get_contents('php://input');
    
    if (!is_writable($file_path)) {
        echo json_encode(['success' => false, 'message' => 'File is read-only (Permission denied)']);
        exit;
    }
    
    if (file_put_contents($file_path, $content) !== false) {
        echo json_encode(['success' => true, 'message' => 'Saved successfully at ' . date('H:i:s')]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to write to disk']);
    }
    exit;
}

// 6. Read File Content (GET)
// Max file size check (e.g., 2MB) to prevent browser crash
if (filesize($file_path) > 2 * 1024 * 1024) {
    die("File is too large ( > 2MB) to edit in the browser.");
}

$content = file_get_contents($file_path);
$is_writable = is_writable($file_path);
$extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

// Map extensions to Ace Editor modes
$modes = [
    'html' => 'html', 'htm' => 'html',
    'php' => 'php',
    'css' => 'css',
    'js' => 'javascript', 'json' => 'json',
    'sql' => 'sql',
    'xml' => 'xml',
    'md' => 'markdown',
    'txt' => 'text',
    'htaccess' => 'apache_conf',
    'py' => 'python',
    'yml' => 'yaml', 'yaml' => 'yaml',
    'ini' => 'ini',
    'conf' => 'ini',
    'sh' => 'sh'
];
$editor_mode = $modes[$extension] ?? 'text';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit: <?= htmlspecialchars(basename($file_path)) ?></title>
    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Ace Editor (CDN) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ext-modelist.js"></script>
    
    <style>
        :root { 
            --primary: #3b82f6; 
            --primary-dark: #2563eb; 
            --bg-dark: #1e1e1e; 
            --text-light: #e5e7eb; 
            --border-dark: #374151;
            --success: #10b981;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Poppins', system-ui, -apple-system, sans-serif; display: flex; flex-direction: column; height: 100vh; background: var(--bg-dark); color: var(--text-light); overflow: hidden; }
        
        /* HEADER / TOOLBAR */
        .editor-header {
            height: 50px;
            background: #252526;
            border-bottom: 1px solid var(--border-dark);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 15px;
        }
        
        .file-info { display: flex; align-items: center; gap: 10px; font-size: 14px; }
        .file-icon { color: #facc15; }
        .file-path { color: #9ca3af; font-family: monospace; }
        .readonly-badge { background: #ef4444; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }

        .toolbar-actions { display: flex; align-items: center; gap: 10px; }
        
        .btn { border: none; padding: 6px 14px; border-radius: 4px; font-size: 13px; font-weight: 500; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: background 0.2s; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-dark); }
        .btn-secondary { background: #374151; color: #e5e7eb; }
        .btn-secondary:hover { background: #4b5563; }
        
        /* Settings Dropdowns */
        .settings-group { display: flex; gap: 5px; border-left: 1px solid #4b5563; padding-left: 10px; margin-left: 5px; }
        select { background: #374151; color: white; border: 1px solid #4b5563; padding: 4px; border-radius: 4px; font-size: 12px; outline: none; cursor: pointer; }

        /* EDITOR AREA */
        #editor { flex: 1; width: 100%; height: calc(100vh - 80px); }

        /* FOOTER / STATUS BAR */
        .status-bar {
            height: 25px;
            background: #007acc;
            color: white;
            font-size: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 15px;
        }
        .status-left, .status-right { display: flex; gap: 15px; }
        
        /* NOTIFICATION TOAST */
        #toast {
            position: fixed; top: 60px; right: 20px;
            background: var(--success); color: white;
            padding: 10px 20px; border-radius: 6px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            font-size: 14px; display: flex; align-items: center; gap: 8px;
            opacity: 0; transform: translateY(-10px); transition: all 0.3s;
            z-index: 9999;
        }
        #toast.active { opacity: 1; transform: translateY(0); }
        #toast.error { background: #ef4444; }

    </style>
</head>
<body>

    <!-- Header -->
    <header class="editor-header">
        <div class="file-info">
            <i class="fas fa-file-code file-icon"></i>
            <span style="font-weight: 600;"><?= htmlspecialchars(basename($file_path)) ?></span>
            <span class="file-path"><?= htmlspecialchars(dirname($file_rel)) ?>/</span>
            <?php if(!$is_writable): ?>
                <span class="readonly-badge" title="You do not have permission to write to this file"><i class="fas fa-lock"></i> Read Only</span>
            <?php endif; ?>
            <span id="unsavedIndicator" style="display:none; color: #facc15; font-size: 12px;">● Unsaved changes</span>
        </div>

        <div class="toolbar-actions">
            <!-- Settings -->
            <div class="settings-group">
                <select id="themeSelect" onchange="changeTheme(this.value)">
                    <option value="monokai">Monokai (Dark)</option>
                    <option value="github">GitHub (Light)</option>
                    <option value="dracula">Dracula</option>
                    <option value="twilight">Twilight</option>
                    <option value="xcode">Xcode</option>
                </select>
                <select id="sizeSelect" onchange="changeFontSize(this.value)">
                    <option value="12">12px</option>
                    <option value="14" selected>14px</option>
                    <option value="16">16px</option>
                    <option value="18">18px</option>
                    <option value="20">20px</option>
                </select>
            </div>

            <?php if($is_writable): ?>
            <button class="btn btn-primary" onclick="saveFile()" id="saveBtn">
                <i class="fas fa-save"></i> Save
            </button>
            <?php endif; ?>
            
            <button class="btn btn-secondary" onclick="window.close()">
                <i class="fas fa-times"></i> Close
            </button>
        </div>
    </header>

    <!-- Editor Container -->
    <div id="editor"><?= htmlspecialchars($content) ?></div>

    <!-- Status Bar -->
    <footer class="status-bar">
        <div class="status-left">
            <span><i class="fas fa-user-circle"></i> <?= htmlspecialchars($user_label) ?></span>
            <span><i class="fas fa-hdd"></i> <?= format_file_size(filesize($file_path)) ?></span>
        </div>
        <div class="status-right">
            <span id="cursorPos">Ln 1, Col 1</span>
            <span><?= strtoupper($extension) ?></span>
            <span>UTF-8</span>
        </div>
    </footer>

    <!-- Toast Notification -->
    <div id="toast"><i class="fas fa-check-circle"></i> <span>Saved successfully</span></div>

    <script>
        // 1. Initialize Ace Editor
        var editor = ace.edit("editor");
        editor.setTheme("ace/theme/monokai"); // Default theme
        editor.session.setMode("ace/mode/<?= $editor_mode ?>");
        editor.setFontSize(14);
        editor.setShowPrintMargin(false);
        editor.session.setUseWrapMode(true);
        editor.setReadOnly(<?= $is_writable ? 'false' : 'true' ?>);
        editor.setOptions({
            enableBasicAutocompletion: true,
            enableLiveAutocompletion: true
        });

        // 2. Track Changes
        var isDirty = false;
        editor.session.on('change', function(delta) {
            if(!isDirty) {
                isDirty = true;
                document.getElementById('unsavedIndicator').style.display = 'inline';
                document.title = "* <?= htmlspecialchars(basename($file_path)) ?>";
            }
        });

        // 3. Status Bar Logic
        editor.selection.on('changeCursor', function() {
            var pos = editor.selection.getCursor();
            document.getElementById('cursorPos').innerText = "Ln " + (pos.row + 1) + ", Col " + (pos.column + 1);
        });

        // 4. Save Logic (AJAX)
        function saveFile() {
            var btn = document.getElementById('saveBtn');
            if(!btn) return;

            var originalText = btn.innerHTML;
            
            // UI Loading state
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
            btn.disabled = true;

            var content = editor.getValue();

            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: content 
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    showToast(data.message, false);
                    isDirty = false;
                    document.getElementById('unsavedIndicator').style.display = 'none';
                    document.title = "<?= htmlspecialchars(basename($file_path)) ?>";
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                showToast("Network Error", true);
                console.error('Error:', error);
            })
            .finally(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
            });
        }

        // 5. Toast Helper
        function showToast(msg, isError) {
            var toast = document.getElementById('toast');
            toast.querySelector('span').innerText = msg;
            
            if(isError) {
                toast.classList.add('error');
                toast.querySelector('i').className = 'fas fa-exclamation-circle';
            } else {
                toast.classList.remove('error');
                toast.querySelector('i').className = 'fas fa-check-circle';
            }
            
            toast.classList.add('active');
            setTimeout(() => { toast.classList.remove('active'); }, 3000);
        }

        // 6. Settings Helpers
        function changeTheme(theme) {
            editor.setTheme("ace/theme/" + theme);
        }
        function changeFontSize(size) {
            editor.setFontSize(parseInt(size));
        }

        // 7. Keybinds (Ctrl+S)
        <?php if($is_writable): ?>
        editor.commands.addCommand({
            name: 'save',
            bindKey: {win: 'Ctrl-S',  mac: 'Command-S'},
            exec: function(editor) {
                saveFile();
            },
            readOnly: false
        });
        <?php endif; ?>

        // 8. Prevent accidental close
        window.onbeforeunload = function() {
            if (isDirty) {
                return "You have unsaved changes. Are you sure you want to leave?";
            }
        };
    </script>
</body>
</html>
<?php
/**
 * Helper: nice file size (Duplicate from index.php to keep this file standalone)
 */
function format_file_size($bytes) {
    if (!is_numeric($bytes) || $bytes <= 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = floor(log($bytes, 1024));
    $power = min($power, count($units) - 1);
    return round($bytes / pow(1024, $power), 2) . ' ' . $units[$power];
}
?>
