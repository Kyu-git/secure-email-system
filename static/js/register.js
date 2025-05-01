document.getElementById('registerForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const fullName = document.getElementById('fullName').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (password !== confirmPassword) {
        alert("Passwords do not match");
        return;
    }

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fullName, email, password })
        });

        const data = await res.json();
        alert(data.message || 'Registration successful');

        if (res.ok) {
            window.location.href = '/login';
        }
    } catch (err) {
        console.error("Registration failed:", err);
        alert('An error occurred. Please try again.');
    }
});
