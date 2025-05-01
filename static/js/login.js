document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    alert(data.message || 'Login successful');

    if (res.status === 200) {
        // Use the redirect URL provided by the backend
        window.location.href = data.redirect || '/dashboard';
    }
});
