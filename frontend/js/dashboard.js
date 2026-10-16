/**
 * PhishGuard AI - Security Analytics Dashboard Controller
 */

(function () {
  'use strict';

  let riskChart = null;
  let trendsChart = null;
  let channelChart = null;
  let allScans = [];

  const dashboard = {
    init() {
      this.bindEvents();
      this.loadDashboardData();
    },

    bindEvents() {
      // Mobile menu
      const mobileBtn = document.getElementById('mobileMenuBtn');
      const sidebar = document.getElementById('sidebar');
      if (mobileBtn && sidebar) {
        mobileBtn.addEventListener('click', () => {
          sidebar.classList.toggle('open');
        });
      }
    },

    async loadDashboardData() {
      await Promise.all([
        this.fetchStats(),
        this.fetchRecentScans()
      ]);
    },

    async fetchStats() {
      try {
        const res = await fetch('/api/dashboard/stats');
        const data = await res.json();

        if (res.ok) {
          this.updateKPIs(data);
          this.renderRiskChart(data.risk_distribution || {});
          this.renderTrendsChart(data.trends || []);
          this.renderChannelChart(data.channel_distribution || {});
          if (data.ml_metrics) {
            this.updateMLMetrics(data.ml_metrics);
          }
        }
      } catch (err) {
        console.error('Failed to load dashboard metrics:', err);
        this.showToast('Unable to connect to analytics database', 'error');
      }
    },

    async fetchRecentScans() {
      try {
        const res = await fetch('/api/scans');
        const data = await res.json();

        if (res.ok) {
          allScans = data.scans || [];
          this.renderScansTable(allScans);
        }
      } catch (err) {
        console.error('Failed to load recent scans:', err);
      }
    },

    updateKPIs(data) {
      document.getElementById('statTotalScans').textContent = data.total_scans || 0;
      document.getElementById('statHighRisk').textContent = data.high_risk_count || 0;
      document.getElementById('statMediumRisk').textContent = data.medium_risk_count || 0;
      document.getElementById('statLowRisk').textContent = data.low_risk_count || 0;
    },

    updateMLMetrics(metrics) {
      if (metrics.accuracy !== undefined) {
        document.getElementById('mlMetricAccuracy').textContent = `${(metrics.accuracy * 100).toFixed(1)}%`;
      }
      if (metrics.precision !== undefined) {
        document.getElementById('mlMetricPrecision').textContent = `${(metrics.precision * 100).toFixed(1)}%`;
      }
      if (metrics.recall !== undefined) {
        document.getElementById('mlMetricRecall').textContent = `${(metrics.recall * 100).toFixed(1)}%`;
      }
      if (metrics.f1 !== undefined) {
        document.getElementById('mlMetricF1').textContent = `${(metrics.f1 * 100).toFixed(1)}%`;
      }
    },

    renderRiskChart(dist) {
      const ctx = document.getElementById('riskDistChart');
      if (!ctx) return;

      const labels = ['High Risk', 'Medium Risk', 'Low Risk', 'Undetermined'];
      const counts = [
        dist['High Risk'] || 0,
        dist['Medium Risk'] || 0,
        dist['Low Risk'] || 0,
        dist['Unable to Determine'] || 0
      ];

      // If all zeros, show empty placeholder counts for initial UX
      const hasData = counts.some(c => c > 0);
      const displayData = hasData ? counts : [0, 0, 0, 0];

      if (riskChart) riskChart.destroy();

      riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: displayData,
            backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#818cf8'],
            borderColor: '#0e172a',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#94a3b8', font: { size: 11 } }
            }
          },
          cutout: '68%'
        }
      });
    },

    renderTrendsChart(trends) {
      const ctx = document.getElementById('scanTrendsChart');
      if (!ctx) return;

      const labels = trends.map(t => t.date);
      const data = trends.map(t => t.count);

      if (trendsChart) trendsChart.destroy();

      trendsChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            label: 'Scans',
            data,
            borderColor: '#00f2fe',
            backgroundColor: 'rgba(0, 242, 254, 0.1)',
            fill: true,
            tension: 0.35,
            pointBackgroundColor: '#00f2fe',
            pointRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { color: 'rgba(56, 189, 248, 0.08)' },
              ticks: { color: '#64748b', font: { size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(56, 189, 248, 0.08)' },
              ticks: { color: '#64748b', precision: 0 }
            }
          }
        }
      });
    },

    renderChannelChart(channels) {
      const ctx = document.getElementById('channelDistChart');
      if (!ctx) return;

      const labels = ['SMS/Chat', 'URL', 'Email', 'Screenshot'];
      const data = [
        channels.message || 0,
        channels.url || 0,
        channels.email || 0,
        channels.screenshot || 0
      ];

      if (channelChart) channelChart.destroy();

      channelChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            data,
            backgroundColor: ['#38bdf8', '#00f2fe', '#818cf8', '#a78bfa'],
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#94a3b8', font: { size: 11 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(56, 189, 248, 0.08)' },
              ticks: { color: '#64748b', precision: 0 }
            }
          }
        }
      });
    },

    renderScansTable(scans) {
      const tbody = document.getElementById('scansTableBody');
      if (!tbody) return;

      if (!scans || scans.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 36px;">
              No scans recorded yet. Perform an analysis on the home page to view telemetry here.
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = scans.map(s => {
        let riskClass = 'risk-undetermined';
        if (s.risk_category === 'High Risk') riskClass = 'risk-high';
        else if (s.risk_category === 'Medium Risk') riskClass = 'risk-medium';
        else if (s.risk_category === 'Low Risk') riskClass = 'risk-low';

        const dateStr = s.timestamp ? new Date(s.timestamp).toLocaleString() : 'Just now';
        const indicatorsText = (s.indicators_summary || []).join(', ') || 'None';

        return `
          <tr>
            <td style="font-size: 0.8rem; color: var(--text-dim); white-space: nowrap;">${this.escapeHtml(dateStr)}</td>
            <td><span style="text-transform: uppercase; font-size: 0.75rem; font-weight: 700; background: rgba(56, 189, 248, 0.1); color: var(--accent-blue); padding: 2px 8px; border-radius: 4px;">${this.escapeHtml(s.scan_type)}</span></td>
            <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${this.escapeHtml(s.target_snippet || '—')}</td>
            <td><span class="badge-risk ${riskClass}" style="font-size: 0.76rem; padding: 3px 8px;">${this.escapeHtml(s.risk_category)}</span></td>
            <td style="font-weight: 700;">${Math.round(s.risk_score || 0)} / 100</td>
            <td style="font-size: 0.82rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${this.escapeHtml(indicatorsText)}">
              ${this.escapeHtml(indicatorsText)}
            </td>
          </tr>
        `;
      }).join('');
    },

    filterScans() {
      const type = document.getElementById('filterScanType').value;
      if (type === 'all') {
        this.renderScansTable(allScans);
      } else {
        const filtered = allScans.filter(s => (s.scan_type || '').toLowerCase() === type);
        this.renderScansTable(filtered);
      }
    },

    async confirmClearHistory() {
      if (!confirm('Are you sure you want to permanently clear all scan records from the database?')) {
        return;
      }

      try {
        const res = await fetch('/api/scans', { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) {
          this.showToast('Scan history successfully purged', 'success');
          this.loadDashboardData();
        } else {
          this.showToast(data.error || 'Failed to clear scans', 'error');
        }
      } catch (err) {
        this.showToast('Network error while deleting scans', 'error');
      }
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

  window.phishDash = dashboard;

  document.addEventListener('DOMContentLoaded', () => {
    dashboard.init();
  });
})();
