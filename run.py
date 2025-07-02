<!DOCTYPE html >
<html lang = "en" >
<head >
    <meta charset = "UTF-8" >
    <meta name = "viewport" content = "width=device-width, initial-scale=1.0" >
    <title > Upload Files - {{current_user.username}} < /title >
    <style >
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg,  # 667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            animation: fadeInUp 0.6s ease;
        }

        .header {
            background: linear-gradient(135deg,  # 667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .header p {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .upload-section {
            padding: 40px;
        }

        .debug-console {
            background:  # f8f9fa;
            border: 2px solid  # e9ecef;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            max-height: 200px;
            overflow-y: auto;
        }

        .debug-console h3 {
            color:  # 495057;
            margin-bottom: 10px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }

        .debug-log {
            color:  # 28a745;
            line-height: 1.4;
        }

        .drop-zone {
            border: 3px dashed  # 667eea;
            border-radius: 15px;
            padding: 60px 40px;
            text-align: center;
            background:  # f8f9ff;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            margin-bottom: 30px;
        }

        .drop-zone: hover {
            border-color:  # 5a67d8;
            background:  # f0f4ff;
            transform: translateY(-2px);
        }

        .drop-zone.dragover {
            border-color:  # 48bb78;
            background:  # f0fff4;
            transform: scale(1.02);
            box-shadow: 0 10px 25px rgba(72, 187, 120, 0.2);
        }

        .drop-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            display: block;
            animation: bounce 2s infinite;
        }

        .drop-text {
            font-size: 1.5rem;
            color:  # 4a5568;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .drop-subtext {
            color:  # 718096;
            font-size: 1rem;
            margin-bottom: 20px;
        }

        .file-input {
            display: none;
        }

        .choose-btn {
            background: linear-gradient(135deg,  # 667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .choose-btn: hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }

        .file-preview {
            display: none;
            background:  # f7fafc;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid  # 667eea;
            animation: slideIn 0.3s ease;
        }

        .file-info {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }

        .file-icon {
            font-size: 2rem;
            margin-right: 15px;
        }

        .file-details h4 {
            color:  # 2d3748;
            margin-bottom: 5px;
        }

        .file-details p {
            color:  # 718096;
            font-size: 0.9rem;
        }

        .upload-btn {
            background: linear-gradient(135deg,  # 48bb78 0%, #38a169 100%);
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .upload-btn: hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(72, 187, 120, 0.4);
        }

        .progress-container {
            display: none;
            margin: 20px 0;
        }

        .progress-bar {
            width: 100 % ;
            height: 12px;
            background:  # e2e8f0;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .progress-fill {
            height: 100 % ;
            background: linear-gradient(90deg,  # 667eea, #764ba2);
            width: 0 % ;
            transition: width 0.2s ease;
            box-shadow: 0 2px 4px rgba(102, 126, 234, 0.3);
        }

        .progress-stats {
            margin-top: 15px;
            animation: slideIn 0.3s ease;
        }

        .progress-info {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 15px;
            margin-bottom: 15px;
            padding: 15px;
            background:  # f8f9ff;
            border-radius: 10px;
            border-left: 4px solid  # 667eea;
        }

        .progress-size, .progress-speed, .progress-time {
            text-align: center;
        }

        .progress-size span, .progress-speed span, .progress-time span {
            display: block;
            font-weight: 600;
            color:  # 2d3748;
        }

        .progress-size: : before {
            content: "📊";
            display: block;
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .progress-speed: : before {
            content: "⚡";
            display: block;
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .progress-time: : before {
            content: "⏱️";
            display: block;
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .progress-actions {
            text-align: center;
        }

        .cancel-btn {
            background: linear-gradient(135deg,  # fc8181 0%, #e53e3e 100%);
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .cancel-btn: hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(229, 62, 62, 0.4);
        }

        .progress-main {
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .progress-detail {
            font-size: 0.9rem;
            color:  # 718096;
        }

        .progress-success {
            color:  # 48bb78;
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .progress-error {
            color:  # e53e3e;
            font-size: 1.2rem;
            margin-bottom: 5px;
        }

        .restrictions {
            background: linear-gradient(135deg,  # ffd89b 0%, #19547b 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            margin-top: 30px;
        }

        .restrictions h4 {
            margin-bottom: 15px;
            font-size: 1.2rem;
        }

        .restrictions ul {
            list-style: none;
        }

        .restrictions li {
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
        }

        .restrictions li: before {
            content: "✓";
            position: absolute;
            left: 0;
            color:  # 68d391;
            font-weight: bold;
        }

        .actions {
            text-align: center;
            margin-top: 30px;
        }

        .view-files-btn {
            background: linear-gradient(135deg,  # 4299e1 0%, #3182ce 100%);
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            display: inline-block;
            transition: all 0.3s ease;
            margin-right: 15px;
        }

        .view-files-btn: hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(66, 153, 225, 0.4);
        }

        .dashboard-btn {
            background: linear-gradient(135deg,  # 718096 0%, #4a5568 100%);
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            display: inline-block;
            transition: all 0.3s ease;
        }

        .dashboard-btn: hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(113, 128, 150, 0.4);
        }

        .flash-messages {
            margin-bottom: 20px;
        }

        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            font-weight: 500;
            animation: slideDown 0.3s ease;
        }

        .alert-success {
            background: linear-gradient(135deg,  # 68d391 0%, #48bb78 100%);
            color: white;
        }

        .alert-error {
            background: linear-gradient(135deg,  # fc8181 0%, #e53e3e 100%);
            color: white;
        }

        .debug-info {
            background:  # f7fafc;
            border: 1px solid  # e2e8f0;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            font-family: monospace;
            font-size: 0.85rem;
            color:  # 4a5568;
            display: none;
        }

        @ keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @ keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @ keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @ keyframes bounce {
            0 %, 20%, 50%, 80%, 100 % {
                transform: translateY(0);
            }
            40 % {
                transform: translateY(-10px);
            }
            60 % {
                transform: translateY(-5px);
            }
        }

        @ media(max-width: 768px) {
            .progress-info {
                grid-template-columns: 1fr;
                gap: 10px;
            }

            .progress-size, .progress-speed, .progress-time {
                padding: 10px;
                background: white;
                border-radius: 8px;
            }
        }
    < /style >
< / head >
< body >
    < div class = "container" >
        < div class = "header" >
            < h1 > 🚀 File Upload Center < /h1 >
            < p > Drag, drop, and manage your files with style < /p >
        < / div >

        < div class = "upload-section" >
            < !-- Debug Console - ->
            < div class = "debug-console" >
                < h3 > 🔍 Debug Console < /h3 >
                < div id = "debugLog" class = "debug-log" > Initializing... < /div >
            < / div >

            < !-- Flash Messages - ->
            < div class = "flash-messages" >
                { % with messages = get_flashed_messages(with_categories=true) % }
                    { % if messages % }
                        { % for category, message in messages % }
                            < div class = "alert alert-{{ 'error' if category == 'error' else 'success' }}" >
                                {{message}}
                            < /div >
                        { % endfor % }
                    { % endif % }
                { % endwith % }
            < /div >

            < !-- Debug Info - ->
            < div id = "debugInfo" class = "debug-info" >
                < strong > Debug Information: < /strong > <br >
                < span id = "debugText" > Ready for upload... < /span >
            < / div >

            < form id = "uploadForm" method = "POST" enctype = "multipart/form-data" >
                < div class = "drop-zone" id = "dropZone" >
                    < span class = "drop-icon" > ☁️ < /span >
                    < div class = "drop-text" > Drop your files here < /div >
                    < div class = "drop-subtext" > or click to browse your computer < /div >
                    < input type = "file" name = "file" id = "fileInput" class = "file-input" >
                    < button type = "button" class = "choose-btn" onclick = "document.getElementById('fileInput').click()" >
                        Choose Files
                    < /button >
                < / div >

                < div id = "filePreview" class = "file-preview" >
                    < div class = "file-info" >
                        < span id = "fileIcon" class = "file-icon" > 📄 < /span >
                        < div class = "file-details" >
                            < h4 id = "fileName" > Selected File < /h4 >
                            < p id = "fileSize" > File size < /p >
                        < / div >
                    < / div >
                    < button type = "submit" class = "upload-btn" > 🚀 Upload File < /button >
                < / div >
            < / form >

            < div class = "progress-container" id = "progressContainer" >
                < div class = "progress-bar" >
                    < div class = "progress-fill" id = "progressFill" > </div >
                < / div >
                < p id = "progressText" style = "text-align: center; margin-top: 10px; color: #667eea; font-weight: 600;" > Uploading... < /p >
            < / div >

            < div class = "restrictions" >
                < h4 > 📋 Upload Guidelines < /h4 >
                < ul >
                    < li > Maximum file size: 1GB(perfect for video and audio files) < /li >
                    < li > Supported types: Video(MP4, MOV, AVI), Audio(MP3, WAV, FLAC), Images, Documents, Archives < /li >
                    < li > Files are securely stored and private to your account < /li >
                    < li > Drag & drop for the smoothest experience < /li >
                < / ul >
            < / div >

            < div class = "actions" >
                < a href = "{{ url_for('main.files') }}" class = "view-files-btn" >
                    📂 View My Files
                < /a >
                < a href = "{{ url_for('main.index') }}" class = "dashboard-btn" >
                    🏠 Dashboard
                < /a >
            < / div >
        < / div >
    < / div >

    < script >
    alert("JavaScript loaded!");
        // Debug logging function
        function debugLog(message) {
            const debugLog = document.getElementById('debugLog');
            const debugText = document.getElementById('debugText');
            const timestamp = new Date().toLocaleTimeString();

            debugLog.innerHTML += ` < br > [${timestamp}] ${message}`;
            debugLog.scrollTop = debugLog.scrollHeight;

            const debugInfo = document.getElementById('debugInfo');
            debugInfo.style.display = 'block';
            debugText.innerHTML += '<br>' + timestamp + ': ' + message;

            console.log('Debug:', message);
        }

        // Get DOM elements
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const filePreview = document.getElementById('filePreview');
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const fileIcon = document.getElementById('fileIcon');
        const progressContainer = document.getElementById('progressContainer');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const uploadForm = document.getElementById('uploadForm');

        debugLog('JavaScript loaded and DOM elements found');

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName= > {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Highlight drop area when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName= > {
            dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName= > {
            dropZone.addEventListener(eventName, unhighlight, false);
        });

        // Handle dropped files
        dropZone.addEventListener('drop', handleDrop, false);

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        function highlight(e) {
            dropZone.classList.add('dragover');
        }

        function unhighlight(e) {
            dropZone.classList.remove('dragover');
        }

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;

            debugLog(`Files dropped: ${files.length}`);

            if (files.length > 0) {
                // Set the files to the input element
                fileInput.files = files;
                showFileInfo(files[0]);
                debugLog(`File set: ${files[0].name}(${files[0].size} bytes)`);
            }
        }

        // Handle file input change
        fileInput.addEventListener('change', function(e) {
            debugLog('File input changed');
            if (e.target.files & & e.target.files.length > 0) {
                showFileInfo(e.target.files[0]);
                debugLog(`File selected: ${e.target.files[0].name}`);
            }
        });

        function showFileInfo(file) {
            fileName.textContent = file.name;
            fileSize.textContent = formatFileSize(file.size);
            fileIcon.textContent = getFileIcon(file.name);
            filePreview.style.display = 'block';
            debugLog(`File info displayed: ${file.name} - ${formatFileSize(file.size)}`);
        }

        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const icons = {
                'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️', 'gif': '🖼️',
                'pdf': '📄', 'doc': '📝', 'docx': '📝',
                'xlsx': '📊', 'csv': '📊', 'pptx': '📊', 'ppt': '📊',
                'zip': '📦', 'py': '🐍', 'js': '⚡',
                'txt': '📄', 'html': '🌐', 'css': '🎨',
                'mp4': '🎬', 'mov': '🎬', 'avi': '🎬', 'mkv': '🎬',
                'mp3': '🎵', 'wav': '🎵', 'flac': '🎵', 'm4a': '🎵'
            };
            return icons[ext] | | '📁';
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function formatTime(seconds) {
            if (!isFinite(seconds) | | seconds < 0) return 'Calculating...';

            if (seconds < 60) {
                return Math.round(seconds) + 's';
            } else if (seconds < 3600) {
                const minutes = Math.floor(seconds / 60);
                const secs = Math.round(seconds % 60);
                return `${minutes}m ${secs}s`;
            } else {
                const hours = Math.floor(seconds / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                return `${hours}h ${minutes}m`;
            }
        }

        // Enhanced form submission
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            debugLog('Form submission started');

            const file = fileInput.files[0];
            if (!file) {
                alert('Please select a file first!');
                debugLog('No file selected');
                return;
            }

            debugLog(`Starting upload for: ${file.name}(${file.size} bytes)`);

            // Create FormData
            const formData = new FormData();
            formData.append('file', file);

            // Add CSRF token if it exists
            const csrfToken = document.querySelector('input[name="csrf_token"]');
            if (csrfToken) {
                formData.append('csrf_token', csrfToken.value);
                debugLog('CSRF token added');
            }

            const xhr = new XMLHttpRequest();

            // Show progress container
            progressContainer.style.display = 'block';
            filePreview.style.display = 'none';

            // Progress tracking variables
            let startTime = Date.now();
            let lastLoaded = 0;
            let lastTime = startTime;

            // Create progress stats container
            let progressStats = document.querySelector('.progress-stats');
            if (!progressStats) {
                progressStats = document.createElement('div');
                progressStats.className = 'progress-stats';
                progressStats.innerHTML = `
                    < div class = "progress-info" >
                        < div class = "progress-size" >
                            < span id = "uploadedSize" > 0 MB < /span > / < span id = "totalSize" > ${formatFileSize(file.size)} < /span >
                        < / div >
                        < div class = "progress-speed" >
                            < span id = "uploadSpeed" > 0 MB/s < /span >
                        < / div >
                        < div class = "progress-time" >
                            < span id = "timeRemaining" > Calculating... < /span >
                        < / div >
                    < / div >
                    < div class = "progress-actions" >
                        < button type = "button" id = "cancelUpload" class = "cancel-btn" > Cancel Upload < /button >
                    < / div >
                `;
                progressContainer.appendChild(progressStats);
            }

            // Cancel functionality
            document.getElementById('cancelUpload').addEventListener('click', function() {
                xhr.abort();
                debugLog('Upload cancelled by user');
            });

            // Upload progress
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable)
                    const now = Date.now();
                    const timeDelta = now - lastTime;
                    const loadedDelta = e.loaded - lastLoaded;

                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete + '%';

                    // Update size info
                    const uploadedSizeEl = document.getElementById('uploadedSize');
                    const totalSizeEl = document.getElementById('totalSize');
                    if (uploadedSizeEl) uploadedSizeEl.textContent = formatFileSize(e.loaded);
                    if (totalSizeEl) totalSizeEl.textContent = formatFileSize(e.total);

                    // Calculate speed(update every 500ms)
                    if (timeDelta > 500) {
                        const speed = loadedDelta / (timeDelta / 1000);
                        const speedMB = speed / (1024 * 1024);
                        const speedEl = document.getElementById('uploadSpeed');
                        if (speedEl) speedEl.textContent = speedMB.toFixed(1) + ' MB/s';

                        // Calculate time remaining
                        const remainingBytes = e.total - e.loaded;
                        const timeRemaining = remainingBytes / speed;
                        const timeEl = document.getElementById('timeRemaining');
                        if (timeEl) timeEl.textContent = formatTime(timeRemaining);

                        lastTime = now;
                        lastLoaded = e.loaded;
                    }

                    progressText.innerHTML = `
                        < div class = "progress-main" >
                            < strong > ${Math.round(percentComplete)} % </strong > completed
                        < /div >
                        < div class = "progress-detail" >
                            ${formatFileSize(e.loaded)} of ${formatFileSize(e.total)} uploaded
                        < /div >
                    `;

                    debugLog(`Progress: ${Math.round(percentComplete)} % `);
                }
            });

            // Upload complete
            xhr.addEventListener('load', function() {
                debugLog(`Upload completed with status: ${xhr.status}`);

                if (xhr.status === 200) {
                    progressText.innerHTML = `
                        < div class = "progress-success" >
                            < strong > ✅ Upload Complete! < /strong >
                        < / div >
                        < div class = "progress-detail" >
                            ${formatFileSize(file.size)} uploaded successfully
                        < /div >
                    `;
                    progressFill.style.width = '100%';

                    const cancelBtn = document.getElementById('cancelUpload');
                    if (cancelBtn) cancelBtn.style.display = 'none';

                    setTimeout(()= > {
                        // Try to redirect, but provide fallback if URL doesn't exist
                        try {
                            window.location.href = "{{ url_for('main.files') }}";
                        } catch (e) {
                            debugLog('Redirect failed, staying on page');
                            window.location.reload();
                        }
                    }, 2000);
                } else {
                    debugLog(`Upload failed with status: ${xhr.status}, response: ${xhr.responseText}`);
                    progressText.innerHTML = `
                        <div class="progress-error">
                            <strong>❌ Upload Failed</strong>
                        </div>
                        <div class="progress-detail">
                            Status: ${xhr.status} - ${xhr.statusText}
                        </div>
                    `;
                    
                    setTimeout(() => {
                        progressContainer.style.display = 'none';
                        filePreview.style.display = 'block';
                        if (progressStats && progressStats.parentNode) {
                            progressStats.parentNode.removeChild(progressStats);
                        }
                    }, 5000);
                }
            });

            // Upload error
            xhr.addEventListener('error', function() {
                debugLog('Upload failed due to network error');
                progressText.innerHTML = `
                    <div class="progress-error">
                        <strong>❌ Network Error</strong>
                    </div>
                    <div class="progress-detail">
                        Please check your connection and try again
                    </div>
                `;
            });

            // Upload aborted
            xhr.addEventListener('abort', function() {
                debugLog('Upload aborted');
                progressText.innerHTML = `
                    <div class="progress-detail">
                        Upload cancelled by user
                    </div>
                `;
                
                setTimeout(() => {
                    progressContainer.style.display = 'none';
                    filePreview.style.display = 'block';
                    if (progressStats && progressStats.parentNode) {
                        progressStats.parentNode.removeChild(progressStats);
                    }
                }, 2000);
            });

            // Set up and send the request
            const currentUrl = window.location.href;
            const actionUrl = uploadForm.action || currentUrl;
            
            debugLog(`Sending POST request to: ${actionUrl}`);
            
            xhr.open('POST', actionUrl, true);
            
            // Don't set Content-Type header - let browser set it with boundary for multipart
            xhr.send(formData);
            
            debugLog('Request sent');
        });

        // Add click handler for drop zone
        dropZone.addEventListener('click', function(e) {
            if (e.target === dropZone || e.target.classList.contains('drop-icon') || 
                e.target.classList.contains('drop-text') || e.target.classList.contains('drop-subtext')) {
                fileInput.click();
                debugLog('Drop zone clicked, opening file dialog');
            }
        });

        debugLog('All event listeners attached');
    </script>
</body>
</html>