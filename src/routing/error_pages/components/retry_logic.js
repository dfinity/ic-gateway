        // Auto-retry functionality
        let retryCount = 0;
        const maxRetries = 5;
        let retryTimer;
        let timeLeft = 30;

        function retryConnection() {
            const button = document.querySelector('.try-again-button');
            const originalText = button.querySelector('.button-text').textContent;
            button.querySelector('.button-text').textContent = 'Refreshing...';
            button.disabled = true;
            button.style.opacity = '0.7';

            setTimeout(() => {
                window.location.reload();
            }, 500);
        }

        function autoRetry() {
            if (retryCount < maxRetries) {
                const retryInfo = document.querySelector('.retry-info');

                if (timeLeft <= 0) {
                    retryCount++;
                    timeLeft = 30;
                    retryConnection();
                } else {
                    // Update the retry message with current countdown
                    const originalMessage = retryInfo.getAttribute('data-original-message') || retryInfo.innerHTML.split('<br>')[0];
                    if (!retryInfo.getAttribute('data-original-message')) {
                        retryInfo.setAttribute('data-original-message', originalMessage);
                    }
                    retryInfo.innerHTML = `${originalMessage}<br>We'll automatically retry in ${timeLeft} seconds.`;
                    timeLeft--;
                }
            }
        }

        retryTimer = setInterval(autoRetry, 1000);

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Enter' || event.key === ' ') {
                const focused = document.activeElement;
                if (focused.classList.contains('try-again-button')) {
                    event.preventDefault();
                    retryConnection();
                }
            }
        });
