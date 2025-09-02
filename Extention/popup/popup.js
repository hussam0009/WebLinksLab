// Check if the token cookie exists for the web app's domain
chrome.cookies.get(
  { url: 'http://127.0.0.1:80', name: 'token' },
  (cookie) => {
    const iframe = document.getElementById('appFrame');
    if (cookie) {
      // Token exists - redirect to dashboard
      iframe.src = 'http://127.0.0.1:80/dashboard';
    } else {
      // No token - show login page
      iframe.src = 'http://127.0.0.1:80/login';
    }
  }
);