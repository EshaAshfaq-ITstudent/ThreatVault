// Dashboard charts (Chart.js, served locally)
(function () {
  if (!window.Chart || !window.CHART) return;
  const C = window.CHART;
  const muted = '#5e6b80';
  const grid = '#e6ebf2';
  const colors = {
    LOGIN_FAIL: '#e8960f', PORT_SCAN: '#2f5bea', FW_BLOCK: '#9aa6b8',
    MALWARE_ALERT: '#ff5a36', PHISH_CLICK: '#7b61ff',
    BRUTEFORCE: '#e8960f', DDOS: '#13968f', MALWARE: '#ff5a36', PHISHING: '#7b61ff',
  };
  const nice = { LOGIN_FAIL: 'Failed logins', PORT_SCAN: 'Port scans', FW_BLOCK: 'Firewall blocks',
    MALWARE_ALERT: 'Malware alerts', PHISH_CLICK: 'Phishing clicks',
    BRUTEFORCE: 'Brute force', DDOS: 'DDoS', MALWARE: 'Malware', PHISHING: 'Phishing' };

  Chart.defaults.color = muted;
  Chart.defaults.font.family = "'IBM Plex Sans', 'Segoe UI', sans-serif";
  Chart.defaults.font.size = 12.5;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.plugins.tooltip.backgroundColor = '#0f1c2e';
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  const legend = { position: 'bottom', labels: { usePointStyle: true, pointStyle: 'circle', boxWidth: 8, padding: 16 } };
  const shortDay = (d) => d.slice(5);

  // Stacked area chart: one layer per event type
  const trendCtx = document.getElementById('trend');
  new Chart(trendCtx, {
    type: 'line',
    data: {
      labels: C.trend.labels.map(shortDay),
      datasets: C.trend.series.map((s) => ({
        label: nice[s.label] || s.label,
        data: s.data,
        borderColor: colors[s.label],
        backgroundColor: colors[s.label] + '33',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
      })),
    },
    options: {
      interaction: { mode: 'index', intersect: false },
      plugins: { legend },
      scales: {
        x: { grid: { display: false } },
        y: { stacked: true, grid: { color: grid }, border: { display: false }, ticks: { maxTicksLimit: 6 } },
      },
    },
  });

  new Chart(document.getElementById('types'), {
    type: 'doughnut',
    data: {
      labels: C.byType.labels.map((l) => nice[l] || l),
      datasets: [{ data: C.byType.data, backgroundColor: C.byType.labels.map((l) => colors[l] || '#9aa6b8'),
        borderColor: '#fff', borderWidth: 3, hoverOffset: 6 }],
    },
    options: { cutout: '70%', plugins: { legend } },
  });

  new Chart(document.getElementById('countries'), {
    type: 'bar',
    data: {
      labels: C.countries.labels,
      datasets: [{ data: C.countries.data, backgroundColor: '#ff5a36', borderRadius: 6, barThickness: 16 }],
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: grid }, border: { display: false }, ticks: { maxTicksLimit: 5 } },
        y: { grid: { display: false }, border: { display: false }, ticks: { color: '#14213a' } },
      },
    },
  });
})();
