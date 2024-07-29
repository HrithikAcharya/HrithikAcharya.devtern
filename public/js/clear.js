document.addEventListener('DOMContentLoaded', (event) => {
    const clearButton = document.getElementById('clearBtn');
    const form = document.getElementById('loginForm');

    clearButton.addEventListener('click', () => {
        // Clear all input fields in the form
        form.reset();
    });
});