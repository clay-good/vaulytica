/**
 * Vaulytica Advanced Visualizations JavaScript
 * 
 * Handles rendering of attack graphs, threat maps, network topology,
 * timelines, and correlation matrices using D3.js
 */

// Global state
let currentTab = 'attack-graph';
let attackGraphData = null;
let threatMapData = null;
let networkTopologyData = null;
let timelineData = null;
let correlationMatrixData = null;

// Tab switching
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.viz-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Update panels
    document.querySelectorAll('.viz-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${tabName}-panel`).classList.add('active');
    
    currentTab = tabName;
    
    // Load data if not already loaded
    if (tabName === 'attack-graph' && !attackGraphData) {
        refreshAttackGraph();
    } else if (tabName === 'threat-map' && !threatMapData) {
        refreshThreatMap();
    } else if (tabName === 'network-topology' && !networkTopologyData) {
        refreshNetworkTopology();
    } else if (tabName === 'timeline' && !timelineData) {
        refreshTimeline();
    } else if (tabName === 'correlation-matrix' && !correlationMatrixData) {
        refreshCorrelationMatrix();
    }
}

// Refresh all visualizations
function refreshAll() {
    refreshAttackGraph();
    refreshThreatMap();
    refreshNetworkTopology();
    refreshTimeline();
    refreshCorrelationMatrix();
}

// Attack Graph
async function refreshAttackGraph() {
    const container = document.getElementById('attack-graph');
    container.innerHTML = '<div class="viz-loading">Loading attack graph...</div>';
    
    try {
        const response = await fetch('/visualizations/attack-graph?limit=50&hours=24');
        const data = await response.json();
        attackGraphData = data;
        
        if (data.nodes && data.nodes.length > 0) {
            renderAttackGraph(data);
            renderAttackGraphStats(data);
        } else {
            container.innerHTML = '<div class="viz-loading">No events to display</div>';
        }
    } catch (error) {
        console.error('Error loading attack graph:', error);
        container.innerHTML = `<div class="viz-error">Error loading attack graph: ${error.message}</div>`;
    }
}

function renderAttackGraph(data) {
    const container = document.getElementById('attack-graph');
    container.innerHTML = '';
    
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    // Create SVG
    const svg = d3.select('#attack-graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.size + 5));
    
    // Create edges
    const edges = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .enter()
        .append('line')
        .attr('class', 'graph-edge')
        .attr('stroke', d => d.color || '#64748b')
        .attr('stroke-width', d => d.width || 2)
        .attr('stroke-dasharray', d => d.dashed ? '5,5' : '0');
    
    // Create nodes
    const nodes = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter()
        .append('circle')
        .attr('class', 'graph-node')
        .attr('r', d => d.size || 10)
        .attr('fill', d => d.color || '#3b82f6')
        .attr('stroke', '#f1f5f9')
        .attr('stroke-width', 2)
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded))
        .on('click', (event, d) => showNodeDetails(d));
    
    // Add labels
    const labels = svg.append('g')
        .selectAll('text')
        .data(data.nodes)
        .enter()
        .append('text')
        .attr('class', 'graph-label')
        .attr('text-anchor', 'middle')
        .attr('dy', d => d.size + 15)
        .text(d => d.label.substring(0, 20));
    
    // Update positions on simulation tick
    simulation.on('tick', () => {
        edges
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        nodes
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
        
        labels
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });
    
    // Drag functions
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

function renderAttackGraphStats(data) {
    const statsContainer = document.getElementById('attack-graph-stats');
    const metadata = data.metadata || {};
    
    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${data.nodes.length}</div>
            <div class="stat-label">Nodes</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${data.edges.length}</div>
            <div class="stat-label">Edges</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${metadata.total_events || 0}</div>
            <div class="stat-label">Events</div>
        </div>
    `;
}

// Threat Map
async function refreshThreatMap() {
    const container = document.getElementById('threat-map');
    container.innerHTML = '<div class="viz-loading">Loading threat map...</div>';
    
    try {
        const response = await fetch('/visualizations/threat-map?limit=50&hours=24');
        const data = await response.json();
        threatMapData = data;
        
        if (data.points && data.points.length > 0) {
            renderThreatMap(data);
            renderThreatMapStats(data);
        } else {
            container.innerHTML = '<div class="viz-loading">No threats to display</div>';
        }
    } catch (error) {
        console.error('Error loading threat map:', error);
        container.innerHTML = `<div class="viz-error">Error loading threat map: ${error.message}</div>`;
    }
}

function renderThreatMap(data) {
    const container = document.getElementById('threat-map');
    container.innerHTML = '';
    
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    // Create SVG
    const svg = d3.select('#threat-map')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Simple world map projection
    const projection = d3.geoMercator()
        .scale(width / 6.5)
        .translate([width / 2, height / 1.5]);
    
    // Draw world outline (simplified)
    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', '#0f172a');
    
    // Draw grid
    const gridSize = 50;
    for (let x = 0; x < width; x += gridSize) {
        svg.append('line')
            .attr('x1', x).attr('y1', 0)
            .attr('x2', x).attr('y2', height)
            .attr('stroke', '#1e293b')
            .attr('stroke-width', 1);
    }
    for (let y = 0; y < height; y += gridSize) {
        svg.append('line')
            .attr('x1', 0).attr('y1', y)
            .attr('x2', width).attr('y2', y)
            .attr('stroke', '#1e293b')
            .attr('stroke-width', 1);
    }
    
    // Draw connections
    if (data.connections) {
        data.connections.forEach(conn => {
            const sourcePos = projection([conn.source.longitude, conn.source.latitude]);
            const destPos = projection([conn.destination.longitude, conn.destination.latitude]);
            
            svg.append('line')
                .attr('x1', sourcePos[0])
                .attr('y1', sourcePos[1])
                .attr('x2', destPos[0])
                .attr('y2', destPos[1])
                .attr('stroke', '#ef4444')
                .attr('stroke-width', 2)
                .attr('stroke-opacity', 0.4)
                .attr('stroke-dasharray', '5,5');
        });
    }
    
    // Draw threat points
    const points = svg.selectAll('circle')
        .data(data.points)
        .enter()
        .append('circle')
        .attr('class', 'map-point')
        .attr('cx', d => projection([d.longitude, d.latitude])[0])
        .attr('cy', d => projection([d.longitude, d.latitude])[1])
        .attr('r', d => Math.min(5 + d.event_count * 2, 20))
        .attr('fill', d => getSeverityColor(d.severity))
        .attr('fill-opacity', 0.7)
        .attr('stroke', '#f1f5f9')
        .attr('stroke-width', 2)
        .on('click', (event, d) => showThreatDetails(d));
    
    // Add labels for major threats
    data.points.filter(p => p.event_count > 5).forEach(point => {
        const pos = projection([point.longitude, point.latitude]);
        svg.append('text')
            .attr('x', pos[0])
            .attr('y', pos[1] - 25)
            .attr('text-anchor', 'middle')
            .attr('fill', '#f1f5f9')
            .attr('font-size', '12px')
            .text(`${point.country} (${point.event_count})`);
    });
}

function renderThreatMapStats(data) {
    const statsContainer = document.getElementById('threat-map-stats');
    const metadata = data.metadata || {};
    
    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${data.points.length}</div>
            <div class="stat-label">Threat Origins</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${data.connections.length}</div>
            <div class="stat-label">Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${metadata.unique_ips || 0}</div>
            <div class="stat-label">Unique IPs</div>
        </div>
    `;
}

// Helper functions
function getSeverityColor(severity) {
    const colors = {
        'CRITICAL': '#dc2626',
        'HIGH': '#f59e0b',
        'MEDIUM': '#3b82f6',
        'LOW': '#64748b',
        'INFO': '#94a3b8'
    };
    return colors[severity] || '#94a3b8';
}

function showNodeDetails(node) {
    alert(`Node: ${node.label}\nType: ${node.type}\nProperties: ${JSON.stringify(node.properties, null, 2)}`);
}

function showThreatDetails(threat) {
    alert(`Location: ${threat.city}, ${threat.country}\nIP: ${threat.ip_address}\nEvents: ${threat.event_count}\nSeverity: ${threat.severity}`);
}

function exportGraph(graphType) {
    alert(`Export functionality for ${graphType} coming soon!`);
}

// Network Topology
async function refreshNetworkTopology() {
    const container = document.getElementById('network-topology');
    container.innerHTML = '<div class="viz-loading">Loading network topology...</div>';

    try {
        const response = await fetch('/visualizations/network-topology?limit=50&hours=24');
        const data = await response.json();
        networkTopologyData = data;

        if (data.nodes && data.nodes.length > 0) {
            renderNetworkTopology(data);
            renderNetworkTopologyStats(data);
        } else {
            container.innerHTML = '<div class="viz-loading">No network data to display</div>';
        }
    } catch (error) {
        console.error('Error loading network topology:', error);
        container.innerHTML = `<div class="viz-error">Error loading network topology: ${error.message}</div>`;
    }
}

function renderNetworkTopology(data) {
    const container = document.getElementById('network-topology');
    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Create SVG
    const svg = d3.select('#network-topology')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Create force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.size + 10));

    // Create edges
    const edges = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .enter()
        .append('line')
        .attr('class', 'graph-edge')
        .attr('stroke', d => d.color || '#3b82f6')
        .attr('stroke-width', d => d.width || 2);

    // Create nodes
    const nodes = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter()
        .append('circle')
        .attr('class', 'graph-node')
        .attr('r', d => d.size || 10)
        .attr('fill', d => d.color || '#10b981')
        .attr('stroke', '#f1f5f9')
        .attr('stroke-width', 2)
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded))
        .on('click', (event, d) => showNodeDetails(d));

    // Add labels
    const labels = svg.append('g')
        .selectAll('text')
        .data(data.nodes)
        .enter()
        .append('text')
        .attr('class', 'graph-label')
        .attr('text-anchor', 'middle')
        .attr('dy', d => d.size + 15)
        .text(d => d.label.substring(0, 15));

    // Update positions on simulation tick
    simulation.on('tick', () => {
        edges
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        nodes
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        labels
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    // Drag functions
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

function renderNetworkTopologyStats(data) {
    const statsContainer = document.getElementById('network-topology-stats');
    const metadata = data.metadata || {};

    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${metadata.total_assets || 0}</div>
            <div class="stat-label">Assets</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #dc2626;">${metadata.compromised_assets || 0}</div>
            <div class="stat-label">Compromised</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${data.edges.length}</div>
            <div class="stat-label">Connections</div>
        </div>
    `;
}

// Timeline
async function refreshTimeline() {
    const container = document.getElementById('timeline');
    container.innerHTML = '<div class="viz-loading">Loading timeline...</div>';

    try {
        const response = await fetch('/visualizations/timeline?limit=100&hours=24');
        const data = await response.json();
        timelineData = data;

        if (data.events && data.events.length > 0) {
            renderTimeline(data);
            renderTimelineStats(data);
        } else {
            container.innerHTML = '<div class="viz-loading">No events to display</div>';
        }
    } catch (error) {
        console.error('Error loading timeline:', error);
        container.innerHTML = `<div class="viz-error">Error loading timeline: ${error.message}</div>`;
    }
}

function renderTimeline(data) {
    const container = document.getElementById('timeline');
    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight;
    const margin = {top: 40, right: 40, bottom: 60, left: 60};
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Create SVG
    const svg = d3.select('#timeline')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const g = svg.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    // Parse timestamps
    const events = data.events.map(e => ({
        ...e,
        timestamp: new Date(e.timestamp)
    }));

    // Create scales
    const xScale = d3.scaleTime()
        .domain(d3.extent(events, d => d.timestamp))
        .range([0, innerWidth]);

    const yScale = d3.scaleBand()
        .domain(events.map((d, i) => i))
        .range([0, innerHeight])
        .padding(0.1);

    // Add axes
    g.append('g')
        .attr('transform', `translate(0,${innerHeight})`)
        .call(d3.axisBottom(xScale).ticks(10))
        .selectAll('text')
        .attr('fill', '#cbd5e1')
        .attr('transform', 'rotate(-45)')
        .style('text-anchor', 'end');

    g.selectAll('.domain, .tick line')
        .attr('stroke', '#475569');

    // Draw timeline events
    g.selectAll('rect')
        .data(events)
        .enter()
        .append('rect')
        .attr('class', 'timeline-event')
        .attr('x', d => xScale(d.timestamp))
        .attr('y', (d, i) => yScale(i))
        .attr('width', 5)
        .attr('height', yScale.bandwidth())
        .attr('fill', d => getSeverityColor(d.severity))
        .on('click', (event, d) => showEventDetails(d));

    // Add event labels for high severity
    events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').forEach((event, i) => {
        g.append('text')
            .attr('x', xScale(event.timestamp) + 10)
            .attr('y', yScale(i) + yScale.bandwidth() / 2)
            .attr('fill', '#f1f5f9')
            .attr('font-size', '10px')
            .text(event.title.substring(0, 30));
    });
}

function renderTimelineStats(data) {
    const statsContainer = document.getElementById('timeline-stats');
    const metadata = data.metadata || {};

    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${data.events.length}</div>
            <div class="stat-label">Events</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${Object.keys(data.grouped || {}).length}</div>
            <div class="stat-label">Time Periods</div>
        </div>
    `;
}

// Correlation Matrix
async function refreshCorrelationMatrix() {
    const container = document.getElementById('correlation-matrix');
    container.innerHTML = '<div class="viz-loading">Loading correlation matrix...</div>';

    const dimension1 = document.getElementById('dimension1').value;
    const dimension2 = document.getElementById('dimension2').value;

    try {
        const response = await fetch(`/visualizations/correlation-matrix?limit=100&hours=24&dimension1=${dimension1}&dimension2=${dimension2}`);
        const data = await response.json();
        correlationMatrixData = data;

        if (data.matrix && data.matrix.length > 0) {
            renderCorrelationMatrix(data);
            renderCorrelationMatrixStats(data);
        } else {
            container.innerHTML = '<div class="viz-loading">No correlations to display</div>';
        }
    } catch (error) {
        console.error('Error loading correlation matrix:', error);
        container.innerHTML = `<div class="viz-error">Error loading correlation matrix: ${error.message}</div>`;
    }
}

function renderCorrelationMatrix(data) {
    const container = document.getElementById('correlation-matrix');
    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight;
    const margin = {top: 80, right: 40, bottom: 80, left: 120};
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Create SVG
    const svg = d3.select('#correlation-matrix')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const g = svg.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    const rows = data.dimensions.rows;
    const columns = data.dimensions.columns;

    // Create scales
    const xScale = d3.scaleBand()
        .domain(columns)
        .range([0, innerWidth])
        .padding(0.05);

    const yScale = d3.scaleBand()
        .domain(rows)
        .range([0, innerHeight])
        .padding(0.05);

    const colorScale = d3.scaleSequential(d3.interpolateRdYlBu)
        .domain([1, 0]);

    // Draw cells
    g.selectAll('rect')
        .data(data.matrix)
        .enter()
        .append('rect')
        .attr('class', 'matrix-cell')
        .attr('x', d => xScale(d.column))
        .attr('y', d => yScale(d.row))
        .attr('width', xScale.bandwidth())
        .attr('height', yScale.bandwidth())
        .attr('fill', d => colorScale(d.value))
        .attr('stroke', 'none')
        .on('click', (event, d) => showCellDetails(d));

    // Add row labels
    g.selectAll('.row-label')
        .data(rows)
        .enter()
        .append('text')
        .attr('class', 'graph-label')
        .attr('x', -10)
        .attr('y', d => yScale(d) + yScale.bandwidth() / 2)
        .attr('text-anchor', 'end')
        .attr('dominant-baseline', 'middle')
        .text(d => d.substring(0, 15));

    // Add column labels
    g.selectAll('.column-label')
        .data(columns)
        .enter()
        .append('text')
        .attr('class', 'graph-label')
        .attr('x', d => xScale(d) + xScale.bandwidth() / 2)
        .attr('y', -10)
        .attr('text-anchor', 'end')
        .attr('transform', d => `rotate(-45, ${xScale(d) + xScale.bandwidth() / 2}, -10)`)
        .text(d => d.substring(0, 15));
}

function renderCorrelationMatrixStats(data) {
    const statsContainer = document.getElementById('correlation-matrix-stats');
    const metadata = data.metadata || {};

    const totalCells = data.matrix.length;
    const nonZeroCells = data.matrix.filter(c => c.count > 0).length;

    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${data.dimensions.rows.length}</div>
            <div class="stat-label">Rows</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${data.dimensions.columns.length}</div>
            <div class="stat-label">Columns</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${nonZeroCells}</div>
            <div class="stat-label">Correlations</div>
        </div>
    `;
}

function showEventDetails(event) {
    alert(`Event: ${event.title}\nTime: ${event.timestamp}\nSeverity: ${event.severity}\nCategory: ${event.category}`);
}

function showCellDetails(cell) {
    alert(`Row: ${cell.row}\nColumn: ${cell.column}\nValue: ${cell.value.toFixed(3)}\nCount: ${cell.count}`);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    refreshAttackGraph();
});

