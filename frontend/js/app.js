/**
 * PhishGuard AI - Main Client Application Logic
 */

(function () {
  'use strict';

  // Sample data presets
  const SAMPLES = {
    message: {
      bank: "URGENT: Your Chase bank account has been suspended due to suspicious activity. Verify your identity immediately at http://chase-security-update.xyz to prevent permanent account suspension.",
      package: "USPS Notice: Your package #US948293 cannot be delivered due to an unpaid postage fee of $1.85. Update address & pay now to avoid package return: http://usps-redelivery-fee.top",
      lottery: "Congratulations! You have been selected as the 2nd prize winner of $250,000 in the 2026 Apple Promo. Reply with your Full Name, Bank Account, and SSN to claim immediately!",
      benign: "Hi Subhash, here is the agenda for our sprint planning session tomorrow at 10:00 AM. Let me know if you need to add any backlog items."
    },
    url: {
      ip: "http://192.168.1.100/secure/login.php?session=harvest",
      typo: "https://paypa1-account-security-update.com/signin?ref=billing",
      subdomain: "http://chase.com.security.verify.account-update.tk/auth",
      benign: "https://en.wikipedia.org/wiki/Phishing"
    },
    email: {
      ceo: {
        sender: "Executive Office <ceo-executive-urgent@mail-outlook-exec.com>",
        subject: "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer",
        body: "Subhash,\n\nI am currently in an all-day executive board meeting with restricted mobile access. We are finalizing a confidential strategic acquisition and need you to execute an immediate domestic wire payment of $48,500 to our escrow attorney.\n\nRouting Number: 021000021\nAccount: 884729103\n\nPlease process immediately and reply directly with the wire confirmation receipt. Do not discuss this with anyone on the floor until the public press release tomorrow morning.\n\nRegards,\nChief Executive Officer"
      },
      payroll: {
        sender: "HR Payroll Department <hr-payroll@corp-workday-portal.com>",
        subject: "Action Required: Verify Direct Deposit Tax Withholding",
        body: "Dear Employee,\n\nOur annual payroll audit detected an inconsistency in your direct deposit bank information. Your upcoming paycheck may be held unless you verify your routing number, account number, and social security number within 24 hours at the following employee self-service link:\n\nhttp://internal-workday-taxupdate.info/login\n\nThank you,\nCorporate HR & Payroll Services"
      },
      newsletter: {
        sender: "Tech Radar <news@techradar-weekly.com>",
        subject: "Tech Radar Weekly - Cybersecurity & Cloud Architecture",
        body: "Hello Reader,\n\nWelcome to this week's edition. In this issue, we review best practices for Zero Trust architectures, API security governance, and multi-cloud resilience.\n\nRead our comprehensive analysis here: https://techradar.com/security/zerotrust\n\nHave a great week ahead!"
      }
    }
  };

  let selectedScreenshotFile = null;

  // App Controller
  const app = {
    init() {
      this.bindNavigation();
      this.bindInputs();
      this.checkUrlHash();
    },

    bindNavigation() {
      // Sidebar tab switching
      document.querySelectorAll('.sidebar .nav-link[data-view]').forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          const viewId = link.getAttribute('data-view');
          this.switchView(viewId);
        });
      });

      // Mobile Menu Toggle
      const mobileBtn = document.getElementById('mobileMenuBtn');
      const sidebar = document.getElementById('sidebar');
      if (mobileBtn && sidebar) {
        mobileBtn.addEventListener('click', () => {
          sidebar.classList.toggle('open');
        });
      }

      // Drag and drop setup
      const dropZone = document.getElementById('dropZone');
      if (dropZone) {
        ['dragenter', 'dragover'].forEach(name => {
          dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
          });
        });

        ['dragleave', 'drop'].forEach(name => {
          dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
          });
        });

        dropZone.addEventListener('drop', (e) => {
          const files = e.dataTransfer.files;
          if (files && files.length > 0) {
            this.handleFile(files[0]);
          }
        });
      }
    },

    bindInputs() {
      const msgInput = document.getElementById('messageInput');
      const counter = document.getElementById('messageCharCount');
      if (msgInput && counter) {
        msgInput.addEventListener('input', () => {
          counter.textContent = `${msgInput.value.length} characters`;
        });
      }
    },

    checkUrlHash() {
      const hash = window.location.hash.replace('#', '');
      if (hash && document.getElementById(hash)) {
        this.switchView(hash);
      }
    },

    switchView(viewId) {
      document.querySelectorAll('.content-view').forEach(view => {
        view.classList.remove('active');
      });

      document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        if (link.getAttribute('data-view') === viewId) {
          link.classList.add('active');
        } else if (link.getAttribute('data-view')) {
          link.classList.remove('active');
        }
      });

      const target = document.getElementById(viewId);
      if (target) {
        target.classList.add('active');
        window.location.hash = viewId;
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }

      // Close mobile sidebar if open
      const sidebar = document.getElementById('sidebar');
      if (sidebar) sidebar.classList.remove('open');
    },

    // Sample Loaders
    loadMessageSample(type) {
      const text = SAMPLES.message[type] || '';
      const input = document.getElementById('messageInput');
      if (input) {
        input.value = text;
        const counter = document.getElementById('messageCharCount');
        if (counter) counter.textContent = `${text.length} characters`;
      }
    },

    loadUrlSample(type) {
      const url = SAMPLES.url[type] || '';
      const input = document.getElementById('urlInput');
      if (input) input.value = url;
    },

    loadEmailSample(type) {
      const sample = SAMPLES.email[type];
      if (sample) {
        document.getElementById('emailSender').value = sample.sender;
        document.getElementById('emailSubject').value = sample.subject;
        document.getElementById('emailBody').value = sample.body;
      }
    },

    // Analysis: Message
    async analyzeMessage(e) {
      e.preventDefault();
      const message = document.getElementById('messageInput').value.trim();
      if (!message) {
        this.showToast('Please enter message text to analyze', 'warning');
        return;
      }

      const loading = document.getElementById('messageLoading');
      const resultContainer = document.getElementById('messageResult');
      loading.style.display = 'block';
      resultContainer.style.display = 'none';

      try {
        const res = await fetch('/api/analyze/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message })
        });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) {
          throw new Error(data.error || 'Server returned an error');
        }

        this.renderResult('messageResult', data, 'Message Threat Analysis');
      } catch (err) {
        loading.style.display = 'none';
        this.renderError('messageResult', err.message);
      }
    },

    // Analysis: URL
    async analyzeUrl(e) {
      e.preventDefault();
      const url = document.getElementById('urlInput').value.trim();
      if (!url) {
        this.showToast('Please enter a target URL', 'warning');
        return;
      }

      const loading = document.getElementById('urlLoading');
      const resultContainer = document.getElementById('urlResult');
      loading.style.display = 'block';
      resultContainer.style.display = 'none';

      try {
        const res = await fetch('/api/analyze/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) {
          throw new Error(data.error || 'URL analysis failed');
        }

        this.renderResult('urlResult', data, 'URL Threat Analysis');
      } catch (err) {
        loading.style.display = 'none';
        this.renderError('urlResult', err.message);
      }
    },

    // Analysis: Email
    async analyzeEmail(e) {
      e.preventDefault();
      const sender = document.getElementById('emailSender').value.trim();
      const subject = document.getElementById('emailSubject').value.trim();
      const body = document.getElementById('emailBody').value.trim();

      if (!subject || !body) {
        this.showToast('Subject and email body are required', 'warning');
        return;
      }

      const loading = document.getElementById('emailLoading');
      const resultContainer = document.getElementById('emailResult');
      loading.style.display = 'block';
      resultContainer.style.display = 'none';

      try {
        const res = await fetch('/api/analyze/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sender, subject, body })
        });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) {
          throw new Error(data.error || 'Email analysis failed');
        }

        this.renderResult('emailResult', data, 'Email Threat Analysis');
      } catch (err) {
        loading.style.display = 'none';
        this.renderError('emailResult', err.message);
      }
    },

    // Screenshot Handling
    handleScreenshotSelect(input) {
      if (input.files && input.files[0]) {
        this.handleFile(input.files[0]);
      }
    },

    handleFile(file) {
      const allowed = ['image/png', 'image/jpeg', 'image/jpg'];
      if (!allowed.includes(file.type)) {
        this.showToast('Only PNG, JPG, and JPEG images are allowed', 'warning');
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        this.showToast('File size exceeds the 10 MB limit', 'warning');
        return;
      }

      selectedScreenshotFile = file;
      const previewBox = document.getElementById('screenshotPreviewBox');
      const previewImg = document.getElementById('screenshotPreviewImg');
      const fileInfo = document.getElementById('screenshotFileInfo');

      const reader = new FileReader();
      reader.onload = (e) => {
        previewImg.src = e.target.result;
        fileInfo.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        previewBox.style.display = 'block';
        document.getElementById('ocrConfirmationSection').style.display = 'none';
        document.getElementById('ocrResult').style.display = 'none';
      };
      reader.readAsDataURL(file);
    },

    async uploadAndExtractOcr() {
      if (!selectedScreenshotFile) {
        this.showToast('Please select a screenshot first', 'warning');
        return;
      }

      const loading = document.getElementById('ocrLoading');
      loading.style.display = 'block';

      const formData = new FormData();
      formData.append('screenshot', selectedScreenshotFile);
      formData.append('extract_only', 'true');

      try {
        const res = await fetch('/api/analyze/screenshot', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) {
          throw new Error(data.error || 'OCR processing failed');
        }

        // Show extracted text for user review and confirmation
        const ocrSection = document.getElementById('ocrConfirmationSection');
        const ocrTextArea = document.getElementById('ocrConfirmedText');
        ocrTextArea.value = data.extracted_text || '';
        ocrSection.style.display = 'block';
        this.showToast('Text extracted via OCR. Please review or edit before scanning.', 'success');
      } catch (err) {
        loading.style.display = 'none';
        this.renderError('ocrResult', err.message);
      }
    },

    async analyzeExtractedText() {
      const text = document.getElementById('ocrConfirmedText').value.trim();
      if (!text) {
        this.showToast('No text available to analyze', 'warning');
        return;
      }

      const loading = document.getElementById('ocrLoading');
      const resultContainer = document.getElementById('ocrResult');
      loading.style.display = 'block';
      resultContainer.style.display = 'none';

      try {
        const res = await fetch('/api/analyze/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, channel: 'screenshot' })
        });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) {
          throw new Error(data.error || 'Analysis failed');
        }

        this.renderResult('ocrResult', data, 'OCR Extracted Message Analysis');
      } catch (err) {
        loading.style.display = 'none';
        this.renderError('ocrResult', err.message);
      }
    },

    // Render Threat Results Card
    renderResult(containerId, data, title) {
      const container = document.getElementById(containerId);
      if (!container) return;

      const risk = data.risk_category || 'Unable to Determine';
      const score = Math.round(data.risk_score !== undefined ? data.risk_score : 50);

      let riskClass = 'risk-undetermined';
      let strokeColor = '#818cf8';
      if (risk === 'High Risk') {
        riskClass = 'risk-high';
        strokeColor = '#ef4444';
      } else if (risk === 'Medium Risk') {
        riskClass = 'risk-medium';
        strokeColor = '#f59e0b';
      } else if (risk === 'Low Risk') {
        riskClass = 'risk-low';
        strokeColor = '#10b981';
      }

      const indicators = data.indicators || [];
      const recommendations = data.recommendations || [];
      const extractedUrls = data.extracted_urls || [];
      const modelDetail = data.model_confidence ? `Model Confidence: ${Math.round(data.model_confidence * 100)}%` : 'Rule Heuristics + ML Ensemble';

      let indicatorsHtml = '';
      if (indicators.length === 0) {
        indicatorsHtml = `<li class="indicator-item flag-neutral">
          <div>
            <div class="indicator-title">No Prominent Threat Signatures Detected</div>
            <div class="indicator-desc">Input did not trigger common social engineering heuristics or credential lure flags. Note: Absence of known indicators does not guarantee absolute safety.</div>
          </div>
        </li>`;
      } else {
        indicators.forEach(item => {
          let flagClass = 'flag-neutral';
          if (item.severity === 'high') flagClass = 'flag-danger';
          else if (item.severity === 'medium') flagClass = 'flag-warning';

          indicatorsHtml += `
            <li class="indicator-item ${flagClass}">
              <div>
                <div class="indicator-title">${this.escapeHtml(item.title || item.name || 'Indicator')}</div>
                <div class="indicator-desc">${this.escapeHtml(item.description || item.reason || '')}</div>
              </div>
            </li>
          `;
        });
      }

      let recsHtml = '';
      if (recommendations.length > 0) {
        recsHtml = `
          <div class="recommendations-box">
            <div class="recommendations-title">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              Recommended Security Actions
            </div>
            <ul class="recommendations-list">
              ${recommendations.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
            </ul>
          </div>
        `;
      }

      let urlBadgesHtml = '';
      if (extractedUrls.length > 0) {
        urlBadgesHtml = `
          <div style="margin: 14px 0;">
            <div style="font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; margin-bottom: 6px;">Extracted URLs (${extractedUrls.length})</div>
            <div style="display:flex; gap: 8px; flex-wrap: wrap;">
              ${extractedUrls.map(u => `<span style="font-family: monospace; font-size: 0.82rem; background: var(--bg-surface); padding: 4px 10px; border-radius: 4px; border: 1px solid var(--border-subtle);">${this.escapeHtml(u)}</span>`).join('')}
            </div>
          </div>
        `;
      }

      container.innerHTML = `
        <div class="result-card">
          <div class="result-header">
            <div class="score-display">
              <div class="score-circle" style="border-color: ${strokeColor}; color: ${strokeColor};">
                <span class="score-val">${score}</span>
                <span class="score-max">/100</span>
              </div>
              <div>
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                  <span class="badge-risk ${riskClass}">${risk}</span>
                  <span style="font-size: 0.82rem; color: var(--text-dim);">${modelDetail}</span>
                </div>
                <h3 style="font-size: 1.2rem; font-weight: 700;">${title}</h3>
                <p style="font-size: 0.85rem; color: var(--text-muted);">${this.escapeHtml(data.summary || 'Heuristic evaluation and threat risk rating complete.')}</p>
              </div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="window.phishApp.copyReport('${containerId}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              Copy Report
            </button>
          </div>

          ${urlBadgesHtml}

          <div style="margin-top: 20px;">
            <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 10px;">Detected Threat Indicators & Signals</div>
            <ul class="indicators-list">
              ${indicatorsHtml}
            </ul>
          </div>

          ${recsHtml}
        </div>
      `;

      container.style.display = 'block';
      container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    },

    renderError(containerId, message) {
      const container = document.getElementById(containerId);
      if (!container) return;
      container.innerHTML = `
        <div class="result-card" style="border-color: var(--risk-high-border);">
          <div style="display:flex; align-items:center; gap: 12px; color: var(--risk-high);">
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <div>
              <h4 style="font-size: 1.05rem;">Analysis Request Error</h4>
              <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 2px;">${this.escapeHtml(message)}</p>
            </div>
          </div>
        </div>
      `;
      container.style.display = 'block';
    },

    copyReport(containerId) {
      const container = document.getElementById(containerId);
      if (!container) return;
      const text = container.innerText;
      navigator.clipboard.writeText(text).then(() => {
        this.showToast('Security report copied to clipboard', 'success');
      }).catch(() => {
        this.showToast('Failed to copy to clipboard', 'warning');
      });
    },

    showToast(message, type = 'info') {
      const toastContainer = document.getElementById('toastContainer');
      if (!toastContainer) return;

      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.textContent = message;

      if (type === 'warning' || type === 'error') {
        toast.style.borderColor = 'var(--risk-high-border)';
      } else if (type === 'success') {
        toast.style.borderColor = 'var(--risk-low-border)';
      }

      toastContainer.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    },

    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  };

  // Expose to window
  window.phishApp = app;

  document.addEventListener('DOMContentLoaded', () => {
    app.init();
  });
})();
