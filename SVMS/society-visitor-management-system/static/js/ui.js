document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.file-input-wrap input[type="file"]').forEach(function (input) {
        input.addEventListener('change', function () {
            var label = input.closest('.file-input-wrap').querySelector('.file-input-label');
            if (label && input.files.length) {
                label.innerHTML = '<strong>' + escapeHtml(input.files[0].name) + '</strong> selected';
            }
        });
    });

    document.querySelectorAll('.flash-messages .alert').forEach(function (alert) {
        setTimeout(function () {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.25s ease';
            setTimeout(function () {
                if (alert.parentNode) alert.parentNode.removeChild(alert);
            }, 260);
        }, 5000);
    });
});

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showToast(message, type) {
    type = type || 'info';
    var container = document.getElementById('toastContainer');
    if (!container) return;

    var toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(function () {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.25s ease';
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 260);
    }, 4000);
}

function togglePasswordVisibility(fieldId) {
    var field = document.getElementById(fieldId);
    if (!field) return;

    var wrapper = field.closest('.password-field');
    var isPassword = field.type === 'password';
    field.type = isPassword ? 'text' : 'password';

    if (wrapper) {
        var open = wrapper.querySelector('.eye-open');
        var closed = wrapper.querySelector('.eye-closed');
        if (open) open.style.display = isPassword ? 'none' : 'block';
        if (closed) closed.style.display = isPassword ? 'block' : 'none';
    }
}

function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
        btn.dataset.originalText = btn.textContent;
        btn.classList.add('btn-loading');
        btn.textContent = 'Please wait';
        btn.disabled = true;
        return;
    }

    btn.classList.remove('btn-loading');
    btn.textContent = btn.dataset.originalText || btn.textContent;
    btn.disabled = false;
}
