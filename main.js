// API endpoints
const API_BASE_URL = 'http://localhost:5000/api';
const API_ENDPOINTS = {
    register: `${API_BASE_URL}/register`,
    login: `${API_BASE_URL}/login`,
    sendEmail: `${API_BASE_URL}/send_email`,
    verifyEmail: `${API_BASE_URL}/verify_email`,
    securityReport: `${API_BASE_URL}/security_report`
};

// DOM Elements
const sections = {
    auth: document.getElementById('authSection'),
    compose: document.getElementById('composeSection'),
    inbox: document.getElementById('inboxSection'),
    reports: document.getElementById('reportsSection')
};

const navButtons = {
    compose: document.getElementById('composeBtn'),
    inbox: document.getElementById('inboxBtn'),
    reports: document.getElementById('reportsBtn')
};

// Authentication
let currentUser = null;

// Show/Hide Sections
function showSection(sectionId) {
    Object.values(sections).forEach(section => {
        section.classList.remove('active');
    });
    sections[sectionId].classList.add('active');
}

// Event Listeners for Navigation
Object.entries(navButtons).forEach(([key, button]) => {
    button.addEventListener('click', () => showSection(key));
});

// Authentication Forms
document.getElementById('showRegister').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelectorAll('.auth-container').forEach(container => {
        container.classList.toggle('hidden');
    });
});

document.getElementById('showLogin').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelectorAll('.auth-container').forEach(container => {
        container.classList.toggle('hidden');
    });
});

// Register Form Handler
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        email: formData.get('email'),
        password: formData.get('password')
    };

    try {
        const response = await fetch(API_ENDPOINTS.register, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            alert('Registration successful! Please login.');
            document.getElementById('showLogin').click();
        } else {
            throw new Error('Registration failed');
        }
    } catch (error) {
        alert('Error during registration: ' + error.message);
    }
});

// Compose Email Handler
document.getElementById('composeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const attachment = document.getElementById('attachment').files[0];

    const emailData = {
        recipient_email: formData.get('to'),
        subject: formData.get('subject'),
        content: formData.get('message'),
        sender_email: currentUser.email
    };

    if (attachment) {
        const reader = new FileReader();
        reader.onload = async () => {
            emailData.attachment = {
                filename: attachment.name,
                content: reader.result
            };
            await sendEmail(emailData);
        };
        reader.readAsDataURL(attachment);
    } else {
        await sendEmail(emailData);
    }
});

// Send Email Function
async function sendEmail(emailData) {
    try {
        const response = await fetch(API_ENDPOINTS.sendEmail, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(emailData)
        });

        if (response.ok) {
            alert('Email sent successfully!');
            document.getElementById('composeForm').reset();
        } else {
            throw new Error('Failed to send email');
        }
    } catch (error) {
        alert('Error sending email: ' + error.message);
    }
}

// Verify Email Function
async function verifyEmail(emailId) {
    try {
        const response = await fetch(`${API_ENDPOINTS.verifyEmail}/${emailId}`);
        const data = await response.json();
        return data.verified;
    } catch (error) {
        console.error('Error verifying email:', error);
        return false;
    }
}

// Load Security Reports
async function loadSecurityReports() {
    try {
        const response = await fetch(API_ENDPOINTS.securityReport);
        const reports = await response.json();
        
        const reportList = document.getElementById('reportList');
        reportList.innerHTML = '';
        
        reports.forEach(report => {
            const reportElement = document.createElement('div');
            reportElement.className = `report-item ${report.severity.toLowerCase()}`;
            reportElement.innerHTML = `
                <h3>${report.attack_type}</h3>
                <p>${report.description}</p>
                <small>Severity: ${report.severity}</small>
                <small>Time: ${new Date(report.timestamp).toLocaleString()}</small>
            `;
            reportList.appendChild(reportElement);
        });
    } catch (error) {
        console.error('Error loading security reports:', error);
    }
}

// Filter Security Reports
document.getElementById('severityFilter').addEventListener('change', (e) => {
    const severity = e.target.value;
    const reports = document.querySelectorAll('.report-item');
    
    reports.forEach(report => {
        if (severity === 'all' || report.classList.contains(severity)) {
            report.style.display = 'block';
        } else {
            report.style.display = 'none';
        }
    });
});

// Initialize the application
function init() {
    showSection('auth');
    // Load initial data if needed
}

init(); 