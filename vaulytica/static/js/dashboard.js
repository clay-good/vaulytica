// Vaulytica Dashboard JavaScript

// Global state
let ws = null;
let timelineChart = null;
let severityChart = null;
let allEvents = [];
let currentFilter = 'all';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing Vaulytica Dashboard...');
    initializeCharts();
    connectWebSocket();
    updateLastUpdateTime();
    setInterval(updateLastUpdateTime, 1000);
});

// WebSocket connection
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
    
    console.log('Connecting to WebSocket:', wsUrl);
    ws = new WebSocket(wsUrl);
    
    ws.onopen = function() {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
    };
    
    ws.onmessage = function(event) {
        const message = JSON.parse(event.data);
        console.log('WebSocket message:', message.type);
        handleWebSocketMessage(message);
    };
    
    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        updateConnectionStatus(false);
    };
    
    ws.onclose = function() {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };
}

// Handle WebSocket messages
function handleWebSocketMessage(message) {
    switch(message.type) {
        case 'initial_data':
            handleInitialData(message.data);
            break;
        case 'new_event':
            handleNewEvent(message.data);
            break;
        case 'stats_update':
            updateStats(message.data);
            break;
        default:
            console.log('Unknown message type:', message.type);
    }
}

// Handle initial data
function handleInitialData(data) {
    console.log('Received initial data');
    updateStats(data.stats);
    allEvents = data.recent_events || [];
    renderEventsTable();
    fetchAndUpdateCharts();
}

// Handle new event
function handleNewEvent(event) {
    console.log('New event:', event.event_id);
    allEvents.unshift(event);
    if (allEvents.length > 100) {
        allEvents.pop();
    }
    renderEventsTable();
    fetchAndUpdateCharts();
}

// Update statistics
function updateStats(stats) {
    document.getElementById('total-events').textContent = stats.total_events || 0;
    document.getElementById('events-24h').textContent = `${stats.events_last_24h || 0} in last 24h`;
    document.getElementById('critical-events').textContent = stats.critical_events || 0;
    document.getElementById('high-events').textContent = `${stats.high_events || 0} high severity`;
    document.getElementById('anomalies-detected').textContent = stats.anomalies_detected || 0;
    document.getElementById('ml-accuracy').textContent = `${(stats.ml_accuracy * 100).toFixed(1)}% ML accuracy`;
    document.getElementById('threats-predicted').textContent = stats.threats_predicted || 0;
    document.getElementById('playbooks-executed').textContent = `${stats.playbooks_executed || 0} playbooks executed`;
}

// Update connection status
function updateConnectionStatus(connected) {
    const statusIndicator = document.getElementById('connection-status');
    const statusText = statusIndicator.querySelector('.status-text');
    
    if (connected) {
        statusIndicator.classList.remove('disconnected');
        statusText.textContent = 'Connected';
    } else {
        statusIndicator.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    }
}

// Update last update time
function updateLastUpdateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    document.getElementById('last-update-time').textContent = timeString;
}

// Initialize charts
function initializeCharts() {
    // Timeline chart
    const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Critical',
                    data: [],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Anomalies',
                    data: [],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#cbd5e1'
                    },
                    grid: {
                        color: '#475569'
                    }
                },
                x: {
                    ticks: {
                        color: '#cbd5e1'
                    },
                    grid: {
                        color: '#475569'
                    }
                }
            }
        }
    });
    
    // Severity chart
    const severityCtx = document.getElementById('severity-chart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#dc2626',
                    '#f59e0b',
                    '#2563eb',
                    '#64748b',
                    '#334155'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#cbd5e1',
                        padding: 15
                    }
                }
            }
        }
    });
}

// Fetch and update charts
async function fetchAndUpdateCharts() {
    try {
        // Fetch timeline data
        const timelineResponse = await fetch('/api/dashboard/timeline');
        const timelineData = await timelineResponse.json();
        
        updateTimelineChart(timelineData);
        
        // Fetch severity distribution
        const severityResponse = await fetch('/api/dashboard/severity');
        const severityData = await severityResponse.json();
        
        updateSeverityChart(severityData);
        
        // Fetch ML insights
        const mlResponse = await fetch('/api/dashboard/ml-insights');
        const mlData = await mlResponse.json();
        
        updateMLInsights(mlData);
    } catch (error) {
        console.error('Error fetching chart data:', error);
    }
}

// Update timeline chart
function updateTimelineChart(data) {
    const labels = data.map(d => new Date(d.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
    const critical = data.map(d => d.critical);
    const high = data.map(d => d.high);
    const anomalies = data.map(d => d.anomalies);
    
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = critical;
    timelineChart.data.datasets[1].data = high;
    timelineChart.data.datasets[2].data = anomalies;
    timelineChart.update();
}

// Update severity chart
function updateSeverityChart(data) {
    severityChart.data.datasets[0].data = [
        data.CRITICAL || 0,
        data.HIGH || 0,
        data.MEDIUM || 0,
        data.LOW || 0,
        data.INFO || 0
    ];
    severityChart.update();
}

// Update ML insights
function updateMLInsights(data) {
    document.getElementById('ml-predictions').textContent = data.total_predictions || 0;
    document.getElementById('ml-anomaly-rate').textContent = `${(data.anomaly_rate * 100).toFixed(1)}%`;
    document.getElementById('ml-threat-rate').textContent = `${(data.threat_rate * 100).toFixed(1)}%`;
    document.getElementById('ml-training-samples').textContent = data.training_samples || 0;
}

// Render events table
function renderEventsTable() {
    const tbody = document.getElementById('events-table-body');
    const filteredEvents = filterEventsBySeverity(allEvents);
    
    if (filteredEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="no-data">No events match the current filter</td></tr>';
        return;
    }
    
    tbody.innerHTML = filteredEvents.slice(0, 50).map(event => `
        <tr>
            <td>${new Date(event.timestamp).toLocaleString()}</td>
            <td><span class="severity-badge ${event.severity.toLowerCase()}">${event.severity}</span></td>
            <td>${event.category}</td>
            <td>${event.title}</td>
            <td>${event.source_system}</td>
            <td><span class="ml-score ${getMLScoreClass(event.ml_anomaly_score)}">${event.ml_anomaly_score ? event.ml_anomaly_score.toFixed(2) : 'N/A'}</span></td>
            <td>${event.ml_threat_level || 'N/A'}</td>
            <td>${event.status}</td>
            <td><button class="btn btn-secondary" onclick="viewEventDetails('${event.event_id}')">View</button></td>
        </tr>
    `).join('');
}

// Filter events by severity
function filterEventsBySeverity(events) {
    if (currentFilter === 'all') {
        return events;
    }
    return events.filter(e => e.severity === currentFilter);
}

// Get ML score class
function getMLScoreClass(score) {
    if (!score) return '';
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
}

// Filter events
function filterEvents() {
    currentFilter = document.getElementById('severity-filter').value;
    renderEventsTable();
}

// Refresh events
function refreshEvents() {
    fetchAndUpdateCharts();
}

// View event details (placeholder)
function viewEventDetails(eventId) {
    alert(`Event details for ${eventId} - Full implementation coming soon!`);
}

