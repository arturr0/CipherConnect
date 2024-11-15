document.addEventListener('DOMContentLoaded', () => {
    const loginButton = document.getElementById('login-button');
    loginButton.addEventListener('click', async () => {
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        // Check for empty inputs
        if (!username || !password) {
            alert('Please enter both username and password.');
            return; // Exit the function if inputs are empty
        }

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                localStorage.setItem('username', username);
                window.location.href = '/chat';
            } else {
                const errorData = await response.json();
                alert(errorData.message || 'Login failed');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        }
    });

    const signUpButton = document.getElementById('sign-up-button');
    signUpButton.addEventListener('click', async () => {
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        // Check for empty inputs
        if (!username || !password) {
            alert('Please enter both username and password.');
            return; // Exit the function if inputs are empty
        }

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                alert('Registration successful! You can now log in.');
            } else {
                const errorData = await response.json();
                alert(errorData.message || 'Registration failed');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        }
    });
    let passwordLenghtAccepted = false;
    let loginLenghtAccepted = false;
    const buttons = document.querySelectorAll('.buttons');
    // Function to update character count, min, and max constraints
    function updateCounter(input, minChars, maxChars) {
        const length = input.value.length;

        // Update counter display
        //counter.innerText = `${length} characters`;

        // Check for min and max characters
        if (length > maxChars) {
            //error.innerText = `Maximum characters allowed: ${maxChars}`;
            input.value = input.value.slice(0, maxChars); // Prevent further input
        } 
        if (input == loginLenght && length >= minChars && length <= maxChars) {
            //error.innerText = ''; // Clear error message
            document.getElementById('iconLoginRejected').style.display = 'none';
            document.getElementById('iconLoginAccepted').style.display = 'block';
            loginLenghtAccepted = true;
        }
        if (input == loginLenght && (length < minChars || length > maxChars)) {
            //error.innerText = ''; // Clear error message
            document.getElementById('iconLoginRejected').style.display = 'block';
            document.getElementById('iconLoginAccepted').style.display = 'none';
            loginLenghtAccepted = false;
        }
        if (input == passwordLenght && length >= minChars && length <= maxChars) {
            //error.innerText = ''; // Clear error message
            document.getElementById('iconPasswordRejected').style.display = 'none';
            document.getElementById('iconPasswordAccepted').style.display = 'block';
            passwordLenghtAccepted = true;
        }
        if (input == passwordLenght && (length < minChars || length > maxChars)) {
            //error.innerText = ''; // Clear error message
            document.getElementById('iconPasswordRejected').style.display = 'block';
            document.getElementById('iconPasswordAccepted').style.display = 'none';
            passwordLenghtAccepted = false;
        }
        if (passwordLenghtAccepted && loginLenghtAccepted) {
            console.log("Both inputs are accepted, enabling buttons.");
            buttons.forEach(button => {
                button.disabled = false;
                button.classList.remove('inactive'); 
                button.classList.add('active'); 
            });
        } else if (!passwordLenghtAccepted || !loginLenghtAccepted) {
            console.log("One or both inputs are not accepted, disabling buttons.");
            buttons.forEach(button => {
                button.disabled = true;
                button.classList.add('inactive'); 
                button.classList.remove('active'); 
            });
        }
        
    }

    // Set up inputs with different character limits
    const loginLenght = document.getElementById('username');
    //const counter1 = document.getElementById('counter1');
    //const error1 = document.getElementById('error1');
    loginLenght.addEventListener('input', () => updateCounter(loginLenght, 1, 20));

    const passwordLenght = document.getElementById('password');
    //const counter2 = document.getElementById('counter2');
    //const error2 = document.getElementById('error2');
    passwordLenght.addEventListener('input', () => updateCounter(passwordLenght, 4, 8));

});