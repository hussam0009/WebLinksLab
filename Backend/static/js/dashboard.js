const cookies = document.cookie.split(';').map(cookie => cookie.trim());
const tokenCookie = cookies.find(cookie => cookie.startsWith('token='));

localStorage.setItem('token',tokenCookie.split("=")[1])
const token = localStorage.getItem('token');
if (!token) {
    window.location.href = '/login';
} 