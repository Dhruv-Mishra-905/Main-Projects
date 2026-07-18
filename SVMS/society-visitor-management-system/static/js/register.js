(function () {
    var emailVerified = false;
    var phoneVerified = false;
    var cooldownTimers = {};

    function byId(id) {
        return document.getElementById(id);
    }

    function setupOtpBoxes(group) {
        var boxes = document.querySelectorAll('[data-otp="' + group + '"]');
        boxes.forEach(function (box, index) {
            box.addEventListener('input', function () {
                box.value = box.value.replace(/\D/g, '').slice(0, 1);
                if (box.value && index < boxes.length - 1) {
                    boxes[index + 1].focus();
                }
                syncOtpHidden(group);
            });

            box.addEventListener('keydown', function (event) {
                if (event.key === 'Backspace' && !box.value && index > 0) {
                    boxes[index - 1].focus();
                }
            });

            box.addEventListener('paste', function (event) {
                event.preventDefault();
                var text = (event.clipboardData || window.clipboardData)
                    .getData('text')
                    .replace(/\D/g, '')
                    .slice(0, 6);
                text.split('').forEach(function (char, textIndex) {
                    if (boxes[textIndex]) boxes[textIndex].value = char;
                });
                syncOtpHidden(group);
                if (boxes[Math.min(text.length, boxes.length) - 1]) {
                    boxes[Math.min(text.length, boxes.length) - 1].focus();
                }
            });
        });
    }

    function syncOtpHidden(group) {
        var hidden = byId(group + '_otp_input');
        if (!hidden) return;
        var boxes = document.querySelectorAll('[data-otp="' + group + '"]');
        hidden.value = Array.from(boxes).map(function (box) {
            return box.value;
        }).join('');
    }

    function clearOtpBoxes(group) {
        document.querySelectorAll('[data-otp="' + group + '"]').forEach(function (box) {
            box.value = '';
        });
        syncOtpHidden(group);
    }

    function formatWait(seconds) {
        seconds = Math.max(1, parseInt(seconds || 0, 10));
        var minutes = Math.floor(seconds / 60);
        var remainder = seconds % 60;
        if (minutes && remainder) return minutes + ' min ' + remainder + ' sec';
        if (minutes) return minutes + ' min';
        return seconds + ' sec';
    }

    function startCooldown(group, seconds, message) {
        var btn = byId(group === 'email' ? 'sendEmailBtn' : 'sendPhoneBtn');
        var status = byId(group + '_otp_status');
        if (!btn || !seconds) return;

        clearInterval(cooldownTimers[group]);
        var originalText = btn.dataset.originalText || btn.textContent;
        btn.dataset.originalText = originalText;
        var remaining = parseInt(seconds, 10);

        function tick() {
            if (remaining <= 0) {
                clearInterval(cooldownTimers[group]);
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Retry in ' + formatWait(remaining);
            if (status && message) {
                status.textContent = message.replace(/\.$/, '') + ' (' + formatWait(remaining) + ')';
                status.className = 'otp-status error';
            }
            remaining -= 1;
        }

        tick();
        cooldownTimers[group] = setInterval(tick, 1000);
    }

    function appendAttempts(message, attemptsRemaining) {
        if (typeof attemptsRemaining !== 'number') return message;
        if (attemptsRemaining <= 0) return message + ' No sends left for this 3-minute window.';
        return message + ' ' + attemptsRemaining + ' send' + (attemptsRemaining === 1 ? '' : 's') + ' left.';
    }

    async function sendOtp(group, url, identityName, identityValue) {
        var btn = byId(group === 'email' ? 'sendEmailBtn' : 'sendPhoneBtn');
        var status = byId(group + '_otp_status');
        var otpPanel = byId(group + '_otp_div');

        if (group === 'email') emailVerified = false;
        if (group === 'phone') phoneVerified = false;

        setButtonLoading(btn, true);
        if (status) {
            status.textContent = 'Sending OTP...';
            status.className = 'otp-status';
        }
        if (otpPanel) otpPanel.style.display = 'block';
        clearOtpBoxes(group);

        var formData = new FormData();
        formData.append(identityName, identityValue);

        var cooldownSeconds = 0;
        var cooldownMessage = '';

        try {
            var response = await fetch(url, { method: 'POST', body: formData });
            var data = await response.json();
            if (data.success) {
                var message = appendAttempts(data.message, data.attempts_remaining);
                if (data.demo_otp) message += ' Demo OTP: ' + data.demo_otp + '.';
                if (status) status.textContent = message;
                showToast(data.live ? 'OTP sent.' : 'Demo OTP generated.', data.live ? 'success' : 'info');

                var firstBox = document.querySelector('[data-otp="' + group + '"][data-index="0"]');
                if (firstBox) firstBox.focus();

                if (data.retry_after) cooldownSeconds = data.retry_after;
            } else {
                if (status) {
                    status.textContent = data.message;
                    status.className = 'otp-status error';
                }
                showToast(data.message || 'Could not send OTP.', 'error');
                if (data.retry_after) {
                    cooldownSeconds = data.retry_after;
                    cooldownMessage = data.message;
                }
            }
        } catch (error) {
            if (status) {
                status.textContent = 'Failed to send OTP.';
                status.className = 'otp-status error';
            }
            showToast('Failed to send OTP.', 'error');
        }

        setButtonLoading(btn, false);
        if (cooldownSeconds) startCooldown(group, cooldownSeconds, cooldownMessage);
    }

    async function verifyOtp(group, url, identityName, identityValue) {
        var otp = byId(group + '_otp_input').value.trim();
        var status = byId(group + '_otp_status');

        if (otp.length !== 6) {
            showToast('Enter the full 6-digit OTP.', 'error');
            return;
        }

        var formData = new FormData();
        formData.append(identityName, identityValue);
        formData.append('otp', otp);

        try {
            var response = await fetch(url, { method: 'POST', body: formData });
            var data = await response.json();
            if (data.success) {
                if (group === 'email') emailVerified = true;
                if (group === 'phone') phoneVerified = true;
                if (status) {
                    status.textContent = (group === 'email' ? 'Email' : 'Phone') + ' verified successfully.';
                    status.className = 'otp-status verified';
                }
                showToast((group === 'email' ? 'Email' : 'Phone') + ' verified.', 'success');
            } else {
                if (group === 'email') emailVerified = false;
                if (group === 'phone') phoneVerified = false;
                if (status) {
                    status.textContent = data.message;
                    status.className = 'otp-status error';
                }
                showToast(data.message || 'OTP verification failed.', 'error');
            }
        } catch (error) {
            showToast('Verification failed.', 'error');
        }
    }

    window.sendEmailOTP = function () {
        var email = byId('email').value.trim();
        if (!email) {
            showToast('Please enter your email first.', 'error');
            return;
        }
        sendOtp('email', window.SVMS_OTP.sendEmailUrl, 'email', email);
    };

    window.verifyEmailOTP = function () {
        var email = byId('email').value.trim();
        verifyOtp('email', window.SVMS_OTP.verifyEmailUrl, 'email', email);
    };

    window.sendPhoneOTP = function () {
        var phone = byId('phone').value.trim();
        if (!/^\d{10}$/.test(phone)) {
            showToast('Enter a valid 10-digit phone number.', 'error');
            return;
        }
        sendOtp('phone', window.SVMS_OTP.sendPhoneUrl, 'phone', phone);
    };

    window.verifyPhoneOTP = function () {
        var phone = byId('phone').value.trim();
        verifyOtp('phone', window.SVMS_OTP.verifyPhoneUrl, 'phone', phone);
    };

    setupOtpBoxes('email');
    setupOtpBoxes('phone');

    var emailInput = byId('email');
    var phoneInput = byId('phone');
    var registerForm = byId('registerForm');

    if (emailInput) {
        emailInput.addEventListener('input', function () {
            emailVerified = false;
        });
    }

    if (phoneInput) {
        phoneInput.addEventListener('input', function () {
            phoneVerified = false;
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', function (event) {
            if (!emailVerified || !phoneVerified) {
                event.preventDefault();
                showToast('Verify email and phone OTP before submitting.', 'error');
                var firstOtpButton = byId(!emailVerified ? 'sendEmailBtn' : 'sendPhoneBtn');
                if (firstOtpButton) firstOtpButton.focus();
            }
        });
    }
})();
