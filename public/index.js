document.addEventListener('DOMContentLoaded', () => {
    const loginButton = document.getElementById('login-button');
    const signUpButton = document.getElementById('sign-up-button');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const buttons = document.querySelectorAll('.buttons');
    const loginCharInfo = document.getElementById('loginInfoText');
    const passwordCharInfo = document.getElementById('passwordInfoText');
    let passwordLengthAccepted = false;
    let loginLengthAccepted = false;

    // Helper function to update the validation icons and button states
    function updateCounter(input, minChars, maxChars) {
        const length = input.value.length;
        if (length > maxChars) {
            
            input.value = input.value.slice(0, maxChars); // Prevent further input
        }
        if (input === usernameInput && length >= minChars && length <= maxChars) {
            document.getElementById('iconLoginRejected').style.display = 'none';
            document.getElementById('iconLoginAccepted').style.display = 'block';
            loginLengthAccepted = true;
        } else if (input === usernameInput) {
            document.getElementById('iconLoginRejected').style.display = 'block';
            document.getElementById('iconLoginAccepted').style.display = 'none';
            loginLengthAccepted = false;
        }

        if (input === passwordInput && length >= minChars && length <= maxChars) {
            document.getElementById('iconPasswordRejected').style.display = 'none';
            document.getElementById('iconPasswordAccepted').style.display = 'block';
            passwordLengthAccepted = true;
        } else if (input === passwordInput) {
            document.getElementById('iconPasswordRejected').style.display = 'block';
            document.getElementById('iconPasswordAccepted').style.display = 'none';
            passwordLengthAccepted = false;
        }

        // Enable or disable buttons based on validation
        if (passwordLengthAccepted && loginLengthAccepted) {
            buttons.forEach(button => {
                button.disabled = false;
                button.classList.remove('inactive');
                button.classList.add('active');
            });
        } else {
            buttons.forEach(button => {
                button.disabled = true;
                button.classList.add('inactive');
                button.classList.remove('active');
            });
        }
    }

    // Set up input listeners for length validation
    usernameInput.addEventListener('input', () => updateCounter(usernameInput, 1, 20));
    passwordInput.addEventListener('input', () => updateCounter(passwordInput, 4, 8));

    // Login functionality
    loginButton.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        // Check for empty inputs
        if (!username || !password) {
            alert('Please enter both username and password.');
            return;
        }

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            // Check if the response is okay (status in the range 200-299)
            if (!response.ok) {
                const errorData = await response.text(); // Read response as text for debugging
                console.error('Error response:', errorData); // Log the raw response for debugging
                //alert(errorData);
                document.getElementById('info').textContent = 'Invalid username or password';
                throw new Error(errorData); // You can throw a new error with the response for catching below
            }

            // Handle JSON response when login is successful
            const data = await response.json();

            // Store the username in local storage
            localStorage.setItem('username', username);
            // Redirect to chat page
            window.location.href = '/chat';

        } catch (error) {
            console.error('Error:', error); // Log the error for debugging
            //alert(error); // Show alert for general errors
            document.getElementById('info').textContent = 'Invalid username or password';

        }
    });

    // Registration functionality
    signUpButton.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        // Check for empty inputs
        if (!username || !password) {
            alert('Please enter both username and password.');
            return;
        }

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                //alert('Registration successful! You can now log in.');
                document.getElementById('info').textContent = 'Registration successful! You can now log in.';
            } else {
                const errorData = await response.json();
                //alert(errorData.message || 'Registration failed');
                //console.log(errorData.message) // Display server message
                document.getElementById('info').textContent =  'User already exists';
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        }
    });
    usernameInput.addEventListener('click', () => { 
        passwordCharInfo.textContent = 'Between 1-20 characters.'
    }); // Detect click
    usernameInput.addEventListener('focus', () => {
        passwordCharInfo.textContent = 'Between 1-20 characters.'

    }); // Detect focus (via Tab or click)
    usernameInput.addEventListener('keydown', (event) => {
    if (event.key === "Tab") {
        passwordCharInfo.textContent = 'Between 1-20 characters.'

    }
    });

    passwordInput.addEventListener('click', () => {
        passwordCharInfo.textContent = 'Beetween 4-8 characters'
    }); // Detect click
    passwordInput.addEventListener('focus', () => {
        passwordCharInfo.textContent = 'Beetween 4-8 characters'
    }); // Detect focus (via Tab or click)
    passwordInput.addEventListener('keydown', (event) => {
    if (event.key === "Tab") {
        passwordCharInfo.textContent = 'Beetween 4-8 characters'
    }
    });

});
