document.getElementById('composeForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const form = document.getElementById('composeForm');
    const formData = new FormData(form);

    try {
        const res = await fetch('/api/send_email', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();

        if (res.status === 200) {
            alert(data.message || 'Email sent successfully!');
            form.reset();
        } else {
            alert(data.error || 'Something went wrong.');
        }

    } catch (error) {
        console.error('Send email error:', error);
        alert('Failed to send email. Please try again later.');
    }
});
