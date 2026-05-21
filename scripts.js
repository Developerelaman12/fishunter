// ===========================
// TYPEWRITER ANIMATION
// ===========================

function initTypewriter() {
    const typewriterElement = document.querySelector('.typewriter');
    if (!typewriterElement) return;

    const text = typewriterElement.textContent;
    typewriterElement.textContent = '';
    
    let index = 0;
    const speed = 100;

    function type() {
        if (index < text.length) {
            typewriterElement.textContent += text.charAt(index);
            index++;
            setTimeout(type, speed);
        } else {
            typewriterElement.style.borderRight = '3px solid var(--accent-color)';
        }
    }

    type();
}

// ===========================
// FORM HANDLING
// ===========================

document.getElementById('searchForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = document.getElementById('urlInput').value.trim();
    const resultsSection = document.getElementById('resultsSection');
    const resultCard = document.getElementById('resultCard');
    const resultStatus = document.getElementById('resultStatus');
    const resultMessage = document.getElementById('resultMessage');

    // Clear previous results
    resultCard.className = 'result-card';

    // Validate URL
    if (!isValidURL(url)) {
        showError(resultStatus, resultMessage, resultsSection, '<i class="bi bi-exclamation-triangle"></i>', 'Пожалуйста, введите корректный URL');
        return;
    }

    // Show loading state
    resultStatus.innerHTML = '<i class="bi bi-hourglass-split"></i>';
    resultMessage.textContent = 'Проверка URL...';
    resultsSection.style.display = 'block';
    
    try {
        const response = await fetch('/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.error) {
            showError(resultStatus, resultMessage, resultsSection, '<i class="bi bi-x-circle"></i>', data.error);
            return;
        }

        if (data.is_phishing) {
            const riskLevel = data.confidence || 0;
            showDanger(resultStatus, resultMessage, resultCard, 
                '<i class="bi bi-shield-exclamation"></i>', 
                `ВНИМАНИЕ! Обнаружены признаки фишинга (уровень риска: ${riskLevel}%)`
            );
        } else {
            const riskLevel = data.confidence || 0;
            showSuccess(resultStatus, resultMessage, resultCard, 
                '<i class="bi bi-shield-check"></i>', 
                `Сайт выглядит безопасно (уровень риска: ${riskLevel}%)`
            );
        }

        // Clear input
        document.getElementById('urlInput').value = '';

    } catch (error) {
        console.error('Error:', error);
        showError(resultStatus, resultMessage, resultsSection, '<i class="bi bi-exclamation-circle"></i>', 'Ошибка при проверке. Попробуйте позже.');
    }
});

// ===========================
// HELPER FUNCTIONS
// ===========================

function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function showSuccess(statusEl, messageEl, cardEl, icon, message) {
    statusEl.innerHTML = icon;
    messageEl.textContent = message;
    cardEl.classList.add('result-safe');
    cardEl.classList.remove('result-danger');
}

function showDanger(statusEl, messageEl, cardEl, icon, message) {
    statusEl.innerHTML = icon;
    messageEl.textContent = message;
    cardEl.classList.add('result-danger');
    cardEl.classList.remove('result-safe');
}

function showError(statusEl, messageEl, resultsSection, icon, message) {
    statusEl.innerHTML = icon;
    messageEl.textContent = message;
    resultsSection.style.display = 'block';
}

// ===========================
// INITIALIZATION
// ===========================

document.addEventListener('DOMContentLoaded', () => {
    initTypewriter();
    
    // Add smooth scroll behavior
    document.documentElement.style.scrollBehavior = 'smooth';
});

// ===========================
// KEYBOARD SHORTCUTS
// ===========================

document.addEventListener('keydown', (e) => {
    // Focus search input with Ctrl+K
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('urlInput').focus();
    }
});

// ===========================
// ACCESSIBILITY IMPROVEMENTS
// ===========================

document.getElementById('urlInput').addEventListener('focus', function() {
    this.parentElement.style.background = 'rgba(45, 45, 45, 0.8)';
});

document.getElementById('urlInput').addEventListener('blur', function() {
    this.parentElement.style.background = 'rgba(45, 45, 45, 0.5)';
});
