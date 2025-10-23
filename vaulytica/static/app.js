// Vaulytica Web UI JavaScript

const API_BASE = 'http://localhost:8000/api';

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadStatistics();
    loadQuestionnaires();
    setupDragAndDrop();
    setupFileInputs();
});

// Tab switching
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.add('hidden');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');
    
    // Add active class to clicked tab
    event.target.classList.add('active');
    
    // Load data for specific tabs
    if (tabName === 'questionnaires') {
        loadQuestionnaires();
    } else if (tabName === 'library') {
        searchLibrary();
    }
}

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE}/statistics`);
        const data = await response.json();
        
        document.getElementById('stat-documents').textContent = data.agent.documents_ingested || 0;
        document.getElementById('stat-questions').textContent = data.agent.questions_answered || 0;
        document.getElementById('stat-questionnaires').textContent = data.agent.questionnaires_processed || 0;
        
        const approvedCount = data.library.by_status?.approved || 0;
        document.getElementById('stat-library').textContent = approvedCount;
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

// Setup drag and drop
function setupDragAndDrop() {
    const docArea = document.getElementById('doc-upload-area');
    const questArea = document.getElementById('quest-upload-area');
    
    [docArea, questArea].forEach(area => {
        area.addEventListener('dragover', (e) => {
            e.preventDefault();
            area.classList.add('dragover');
        });
        
        area.addEventListener('dragleave', () => {
            area.classList.remove('dragover');
        });
        
        area.addEventListener('drop', (e) => {
            e.preventDefault();
            area.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                if (area.id === 'doc-upload-area') {
                    document.getElementById('doc-file-input').files = files;
                } else {
                    document.getElementById('quest-file-input').files = files;
                }
            }
        });
    });
}

// Setup file inputs
function setupFileInputs() {
    document.getElementById('doc-file-input').addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name;
        if (fileName) {
            document.getElementById('doc-upload-area').innerHTML = `
                <p style="font-size: 3em; margin-bottom: 10px;">✅</p>
                <p style="font-size: 1.2em; color: #667eea;">${fileName}</p>
            `;
        }
    });
    
    document.getElementById('quest-file-input').addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name;
        if (fileName) {
            document.getElementById('quest-upload-area').innerHTML = `
                <p style="font-size: 3em; margin-bottom: 10px;">✅</p>
                <p style="font-size: 1.2em; color: #667eea;">${fileName}</p>
            `;
        }
    });
}

// Upload document
async function uploadDocument() {
    const fileInput = document.getElementById('doc-file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        showMessage('doc-message', 'Please select a file', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('document_type', document.getElementById('doc-type').value);
    
    const title = document.getElementById('doc-title').value;
    if (title) formData.append('title', title);
    
    const tags = document.getElementById('doc-tags').value;
    if (tags) formData.append('tags', tags);
    
    showMessage('doc-message', 'Uploading document...', 'loading');
    
    try {
        const response = await fetch(`${API_BASE}/documents/upload`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Upload failed');
        }
        
        const data = await response.json();
        showMessage('doc-message', `✅ Document uploaded successfully! (${data.word_count} words)`, 'success');
        
        // Reset form
        fileInput.value = '';
        document.getElementById('doc-title').value = '';
        document.getElementById('doc-tags').value = '';
        resetUploadArea('doc-upload-area');
        
        // Reload statistics
        loadStatistics();
        
    } catch (error) {
        showMessage('doc-message', `❌ Upload failed: ${error.message}`, 'error');
    }
}

// Upload questionnaire
async function uploadQuestionnaire() {
    const fileInput = document.getElementById('quest-file-input');
    const file = fileInput.files[0];
    const title = document.getElementById('quest-title').value;
    
    if (!file) {
        showMessage('quest-message', 'Please select a file', 'error');
        return;
    }
    
    if (!title) {
        showMessage('quest-message', 'Please enter a title', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    
    const vendor = document.getElementById('quest-vendor').value;
    if (vendor) formData.append('vendor_name', vendor);
    
    showMessage('quest-message', 'Processing questionnaire... This may take a few minutes.', 'loading');
    
    try {
        const response = await fetch(`${API_BASE}/questionnaires/upload`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Processing failed');
        }
        
        const data = await response.json();
        showMessage('quest-message', 
            `✅ Questionnaire processed! ${data.answered_questions}/${data.total_questions} questions answered (${data.high_confidence_answers} high confidence)`, 
            'success'
        );
        
        // Reset form
        fileInput.value = '';
        document.getElementById('quest-title').value = '';
        document.getElementById('quest-vendor').value = '';
        resetUploadArea('quest-upload-area');
        
        // Reload questionnaires and statistics
        loadQuestionnaires();
        loadStatistics();
        
    } catch (error) {
        showMessage('quest-message', `❌ Processing failed: ${error.message}`, 'error');
    }
}

// Load questionnaires
async function loadQuestionnaires() {
    try {
        const response = await fetch(`${API_BASE}/questionnaires`);
        const data = await response.json();
        
        const listDiv = document.getElementById('questionnaire-list');
        
        if (data.questionnaires.length === 0) {
            listDiv.innerHTML = '<p style="color: #999; text-align: center; padding: 40px;">No questionnaires yet. Upload one to get started!</p>';
            return;
        }
        
        listDiv.innerHTML = data.questionnaires.map(q => `
            <div class="questionnaire-item">
                <h3>${q.title}</h3>
                <div class="meta">
                    ${q.vendor_name ? `Vendor: ${q.vendor_name} • ` : ''}
                    Status: <span class="badge badge-${q.status === 'completed' ? 'success' : 'info'}">${q.status}</span>
                </div>
                <div class="progress">
                    <span>📊 ${q.answered_questions}/${q.total_questions} answered</span>
                    <span>✅ ${q.high_confidence_answers} high confidence</span>
                    <span>⚠️ ${q.low_confidence_answers} need review</span>
                </div>
                <div class="actions">
                    <button class="btn btn-small" onclick="exportQuestionnaire('${q.questionnaire_id}', 'csv')">📥 Export CSV</button>
                    <button class="btn btn-small" onclick="exportQuestionnaire('${q.questionnaire_id}', 'excel')">📥 Export Excel</button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Failed to load questionnaires:', error);
    }
}

// Export questionnaire
async function exportQuestionnaire(questionnaireId, format) {
    try {
        const url = `${API_BASE}/questionnaires/${questionnaireId}/export/${format}`;
        window.open(url, '_blank');
    } catch (error) {
        alert(`Export failed: ${error.message}`);
    }
}

// Search library
async function searchLibrary() {
    const query = document.getElementById('library-search').value;
    
    try {
        const response = await fetch(`${API_BASE}/library/search`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: query || null,
                approval_status: 'approved',
                limit: 50
            })
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('library-results');
        
        if (data.answers.length === 0) {
            resultsDiv.innerHTML = '<p style="color: #999; text-align: center; padding: 40px;">No approved answers found.</p>';
            return;
        }
        
        resultsDiv.innerHTML = data.answers.map(a => `
            <div class="questionnaire-item" style="margin-bottom: 15px;">
                <h3 style="font-size: 1em; color: #667eea;">Q: ${a.question_text}</h3>
                <p style="margin: 10px 0; color: #333;"><strong>A:</strong> ${a.answer_text}</p>
                <div class="meta">
                    Category: ${a.category} • 
                    Confidence: ${(a.confidence_score * 100).toFixed(0)}% • 
                    Version: ${a.version} • 
                    Sources: ${a.sources.join(', ')}
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Library search failed:', error);
    }
}

// Answer single question
async function answerSingleQuestion() {
    const question = document.getElementById('single-question').value;
    const category = document.getElementById('single-category').value;
    
    if (!question) {
        showMessage('single-answer', 'Please enter a question', 'error');
        return;
    }
    
    showMessage('single-answer', 'Generating answer...', 'loading');
    
    try {
        const response = await fetch(`${API_BASE}/questions/answer`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                question_text: question,
                question_type: 'free_text',
                category: category || null
            })
        });
        
        if (!response.ok) {
            throw new Error('Answer generation failed');
        }
        
        const data = await response.json();
        
        const answerDiv = document.getElementById('single-answer');
        answerDiv.innerHTML = `
            <div style="background: #f8f9ff; padding: 20px; border-radius: 8px; margin-top: 20px; border-left: 4px solid ${data.requires_review ? '#ff9800' : '#4caf50'};">
                <h3 style="color: #333; margin-bottom: 10px;">Answer</h3>
                <p style="color: #333; line-height: 1.6; margin-bottom: 15px;">${data.answer_text}</p>
                <div style="display: flex; gap: 15px; margin-bottom: 15px;">
                    <span class="badge ${data.confidence_score >= 0.7 ? 'badge-success' : 'badge-warning'}">
                        Confidence: ${(data.confidence_score * 100).toFixed(0)}%
                    </span>
                    ${data.from_library ? '<span class="badge badge-info">From Library</span>' : ''}
                    ${data.requires_review ? '<span class="badge badge-warning">Needs Review</span>' : ''}
                </div>
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; color: #667eea; font-weight: 500;">View Sources & Reasoning</summary>
                    <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 5px;">
                        <p style="margin-bottom: 10px;"><strong>Reasoning:</strong> ${data.reasoning}</p>
                        <p><strong>Sources:</strong></p>
                        <ul style="margin-left: 20px;">
                            ${data.sources.map(s => `<li>${s.document_title}</li>`).join('')}
                        </ul>
                    </div>
                </details>
            </div>
        `;
        
        loadStatistics();
        
    } catch (error) {
        showMessage('single-answer', `❌ Failed to generate answer: ${error.message}`, 'error');
    }
}

// Helper functions
function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    
    if (type === 'loading') {
        element.innerHTML = `
            <div class="loading">
                <div class="spinner"></div>
                <p>${message}</p>
            </div>
        `;
    } else {
        element.innerHTML = `<div class="${type}">${message}</div>`;
        
        // Auto-hide success/error messages after 5 seconds
        if (type !== 'loading') {
            setTimeout(() => {
                element.innerHTML = '';
            }, 5000);
        }
    }
}

function resetUploadArea(areaId) {
    const area = document.getElementById(areaId);
    const isDoc = areaId === 'doc-upload-area';
    
    area.innerHTML = `
        <p style="font-size: 3em; margin-bottom: 10px;">${isDoc ? '📁' : '📋'}</p>
        <p style="font-size: 1.2em; color: #667eea; margin-bottom: 5px;">Click to upload or drag and drop</p>
        <p style="color: #999; font-size: 0.9em;">${isDoc ? 'Supported: PDF, DOCX, TXT, MD, CSV, XLSX' : 'Supported: CSV, XLSX'}</p>
    `;
}

