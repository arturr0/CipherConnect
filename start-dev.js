const { exec } = require('child_process');

// Start nodemon
const server = exec('npx nodemon server.js');

server.stdout.on('data', (data) => {
    console.log(data);
    // Check for the server start message
    if (data.includes('Server is running on')) {
        console.log('Server is running. Starting browser-sync...');
        // Start browser-sync after a delay of 2 seconds
        setTimeout(() => {
            exec('browser-sync start --config bs-config.js', (error, stdout, stderr) => {
                if (error) {
                    console.error(`Error starting browser-sync: ${error.message}`);
                    return;
                }
                console.log(stdout);
                console.error(stderr);
            });
        }, 2000); // 2000 ms delay
    }
});
