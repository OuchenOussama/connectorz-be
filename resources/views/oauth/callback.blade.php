<!DOCTYPE html>
<html>
<head>
    <title>OAuth Authorization</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <div id="message">
        <h2>Processing authorization...</h2>
    </div>
    
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const success = urlParams.get('success') === 'true';
        const connectorId = urlParams.get('connectorId');
        const error = urlParams.get('error');
        
        const messageDiv = document.getElementById('message');
        
        if (success) {
            messageDiv.innerHTML = `
                <h2 class="success">✓ Authorization Successful</h2>
                <p>Your ${connectorId} account has been connected successfully.</p>
                <p>You can close this window.</p>
            `;
            
            // Notify parent window
            if (window.opener) {
                window.opener.postMessage({ 
                    success: true, 
                    connectorId: connectorId 
                }, '*');
            }
        } else {
            messageDiv.innerHTML = `
                <h2 class="error">✗ Authorization Failed</h2>
                <p>Failed to connect your account: ${error || 'Unknown error'}</p>
                <p>Please try again.</p>
            `;
            
            // Notify parent window
            if (window.opener) {
                window.opener.postMessage({ 
                    success: false, 
                    error: error || 'Unknown error' 
                }, '*');
            }
        }
        
        // Auto-close after 3 seconds
        setTimeout(() => {
            window.close();
        }, 3000);
    </script>
</body>
</html>