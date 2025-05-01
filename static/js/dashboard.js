document.addEventListener("DOMContentLoaded", () => {
    loadUserProfile();
    loadInbox();
  });
  
  function loadUserProfile() {
    fetch('/api/profile')
      .then(res => res.json())
      .then(data => {
        document.getElementById("username").textContent = data.username || 'User';
        document.getElementById("user-email").textContent = data.email || 'user@example.com';
      })
      .catch(err => console.error("Profile fetch error:", err));
  }
  
  function loadInbox() {
    fetch('/api/inbox')
      .then(res => res.json())
      .then(messages => {
        const inboxList = document.getElementById("inbox-list");
        inboxList.innerHTML = ''; // Clear old content
  
        if (messages.length === 0) {
          inboxList.innerHTML = '<p>No messages in your inbox.</p>';
          return;
        }
  
        messages.forEach(msg => {
          const messageEl = document.createElement("div");
          messageEl.className = "inbox-message";
          messageEl.innerHTML = `
            <strong>From:</strong> ${msg.sender} <br>
            <strong>Subject:</strong> ${msg.subject} <br>
            <p>${msg.body}</p>
          `;
          inboxList.appendChild(messageEl);
        });
      })
      .catch(err => {
        console.error("Inbox fetch error:", err);
        document.getElementById("inbox-list").innerHTML = '<p>Error loading messages.</p>';
      });
  }
  
  function logout() {
    // Clear token or session, redirect to login
    fetch('/api/logout', { method: 'POST' })
      .then(() => {
        window.location.href = '/login';
      })
      .catch(err => console.error("Logout error:", err));
  }
  