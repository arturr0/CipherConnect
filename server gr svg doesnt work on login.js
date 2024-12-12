require('dotenv').config();
const express = require('express');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const JWT_SECRET = process.env.JWT_SECRET;
const uploadsDir = path.join(__dirname, 'uploads'); // Adjust the path according to your project structure

app.use('/uploads', express.static(uploadsDir)); // Serve images from the uploads directory
//app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Serve static files from the uploads directory
//app.use('/uploads', express.static(uploadsDir));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
const db = new sqlite3.Database('chat.db');
app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');


// Initialize multer with the defined storage


// Handle file upload route

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir); // Set the destination to 'uploads' directory
    },
    filename: function (req, file, cb) {
        const uniqueFileName = `uploaded_image_${Date.now()}_${file.originalname}`;
        cb(null, uniqueFileName);
    }
});
const upload = multer({ storage: storage });

// Handle file uploads
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }
    // Send the uploaded file path
    res.json({ filePath: `/uploads/${req.file.filename}` });
});

// Encryption/Decryption functions


const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Ensure it's a hex string
const IV_LENGTH = 16; // AES block size

if (ENCRYPTION_KEY.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be 32 bytes long.");
}

// Function to encrypt a message
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Return IV + encrypted text
}

// Function to decrypt a message
function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption failed:', error);
        return null; // Return null or handle error as needed
    }
}


// db.close((err) => {
//     if (err) {
//         console.error('Error closing the database connection:', err.message);
//     } else {
//         console.log('Database connection closed.');
//         // Now delete the file
        
//     }
// });

// Initialize the SQLite database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        socketId TEXT,
        receiver INTEGER,
        groupRec INTEGER, 
        profileImage BLOB,
        FOREIGN KEY (receiver) REFERENCES users(id),
        FOREIGN KEY (groupRec) REFERENCES groups(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        groupID INTEGER,
        senderId INTEGER,
        recId INTEGER,
        message TEXT,
        read INTEGER NOT NULL,
        sendTime TEXT NOT NULL,
        toDelete INTEGER DEFAULT 0, 
        FOREIGN KEY (senderId) REFERENCES users(id),
        FOREIGN KEY (recId) REFERENCES users(id)
    );`);

    db.run(`CREATE TABLE IF NOT EXISTS GroupMessages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        groupId INTEGER,
        senderId INTEGER,
        RecId INTEGER,
        message TEXT,
        read INTEGER NOT NULL,
        sendTime TEXT NOT NULL,
        toDelete INTEGER DEFAULT 0,
        FOREIGN KEY (groupId) REFERENCES groups(id),
        FOREIGN KEY (senderId) REFERENCES users(id),
        FOREIGN KEY (RecId) REFERENCES users(id)
    );`);

    db.run(`CREATE TABLE IF NOT EXISTS blocked (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blocker INTEGER,
        blocked INTEGER,
        FOREIGN KEY (blocker) REFERENCES users(id),
        FOREIGN KEY (blocked) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inviting INTEGER,
        invited INTEGER,
        accepted INTEGER NOT NULL,
        FOREIGN KEY (inviting) REFERENCES users(id),
        FOREIGN KEY (invited) REFERENCES users(id)
    )`, (err) => {
        if (err) {
            console.error('Error creating friends table:', err);
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        creator INTEGER,
        name TEXT,
        avatar BLOB,
        FOREIGN KEY (creator) REFERENCES users(id)
    );`);

    db.run(`CREATE TABLE IF NOT EXISTS groupInvite (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inviting INTEGER,
        invited INTEGER,
        groupId INTEGER,
        groupName TEXT,
        accepted INTEGER DEFAULT 0,
        FOREIGN KEY (groupId) REFERENCES groups(id),
        FOREIGN KEY (groupName) REFERENCES groups(name),
        FOREIGN KEY (inviting) REFERENCES users(id),
        FOREIGN KEY (invited) REFERENCES users(id)
    );`);
}); 

// Serve the authorization page
// Serve the main page
app.get('/', (req, res) => {
    res.render('index');
});

// Serve the chat page (after authentication)
app.get('/chat', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/'); // Redirect to login if not authenticated
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect('/'); // Redirect to login if token is invalid
        }
        res.render('chat'); // Render chat.pug for authenticated users
    });
});

// User registration with validation
// User registration with validation
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Initialize an array to collect error messages
    const errors = [];

    // Validate username length
    if (!username || username.length < 1 || username.length > 20) {
        errors.push('Username must be between 1 and 20 characters.');
    }

    // Validate password length
    if (!password || password.length < 4 || password.length > 8) {
        errors.push('Password must be between 4 and 8 characters.');
    }

    // If there are any errors, return them
    if (errors.length > 0) {
        return res.status(400).json({ message: errors.join(' ') });
    }

    // Hash the password and save the user
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
            if (err) return res.status(500).json({ message: 'User already exists' });
            res.status(200).json({ message: 'User registered successfully' });
        });
    });
});

// User login with validation
// User login with validation
// User login with validation
// User login with validation
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Initialize an array to collect error messages
    const errors = [];

    // Validate username length
    if (!username || username.length < 1 || username.length > 20) {
        errors.push('Username must be between 1 and 20 characters.');
    }

    // Validate password length
    if (!password || password.length < 4 || password.length > 8) {
        errors.push('Password must be between 4 and 8 characters.');
    }

    // If there are any errors, return them
    if (errors.length > 0) {
        return res.status(400).json({ message: errors.join(' ') }); // Return JSON error message
    }

    // Check if user exists
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Invalid username or password' }); // Return JSON error message
        }

        // Compare the password with the hashed password
        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) {
                return res.status(401).json({ message: 'Invalid username or password' }); // Return JSON error message
            }

            // Generate JWT token and set it as a cookie
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, {
                httpOnly: true, 
                secure: true, 
                sameSite: 'None', 
                maxAge: 3600000 // 1 hour in milliseconds
            });
            
            // Redirect to /chat on successful login
            return res.status(200).json({ message: 'Login successful' }); // Return JSON success message
        });
    });
});





// Socket.IO handling
io.on('connection', (socket) => {
    //console.log('A user connected with socket ID:', socket.id);
    
    // Socket listener for chat messages
    socket.on('chatMessage', ({ username, messageSent, receiver, sendTime, storeMessage }) => {
        // Find sender's ID using socketId
        db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, sender) => {
            if (err || !sender) {
                console.error('Sender not found for socket:', socket.id);
                return;
            }
    
            // Find receiver's ID by username
            db.get('SELECT id, socketId, receiver FROM users WHERE username = ?', [receiver], (err, rec) => {
                if (err || !rec) {
                    console.error('Receiver not found:', receiver);
                    return;
                }
    
                console.log(`Checking block status between sender: ${sender.id} and receiver: ${rec.id}`);
    
                // Check if either the sender or receiver has blocked the other
                db.get(`
                    SELECT 1 
                    FROM blocked 
                    WHERE (blocker = ? AND blocked = ?) 
                       OR (blocker = ? AND blocked = ?)`,
                    [sender.id, rec.id, rec.id, sender.id],
                    (err, blocked) => {
                        if (err) {
                            console.error('Error checking block status:', err);
                            return;
                        }
    
                        if (blocked) {
                            // If blocked, do not send or store the message
                            console.log(`Message blocked: Sender ${username} is blocked from sending to ${receiver}`);
                            socket.emit('messageBlocked', { message: 'Message blocked due to user restrictions.' });
                            return;
                        }
    
                        // Encrypt the message
                        const encryptedMessage = encrypt(messageSent);
    
                        // Log the encrypted message to verify
                        console.log('Encrypted message being sent:', encryptedMessage);
                        if(rec.receiver === sender.id && storeMessage) {
                        // Insert encrypted message into database
                            db.run('INSERT INTO messages (senderId, recId, message, read, sendTime) VALUES (?, ?, ?, ?, ?)', 
                                [sender.id, rec.id, encryptedMessage, 0, sendTime], 
                                function (err) {
                                    if (err) {
                                        console.error('Error saving message:', err);
                                        return;
                                    }

                                    // Send message with sendTime to the receiver
                                    io.to(rec.socketId).emit('message', {
                                        user: username,          // Sender's username
                                        message: messageSent,     // Original (unencrypted) message to display
                                        date: sendTime,            // Include the stored sendTime
                                        store: storeMessage
                                    });

                                    // Check if the receiver's `receiver` matches the sender's ID
                                    if (rec.receiver === sender.id) {
                                        // Update the message 'read' status
                                        db.run('UPDATE messages SET read = 1 WHERE recId = ? AND senderId = ?', 
                                            [rec.id, sender.id], 
                                            function (err) {
                                                if (err) {
                                                    console.error('Error updating message read status:', err);
                                                } else {
                                                    console.log(`Messages marked as read for receiver: ${receiver}`);
                                                }
                                            });
                                        }
                                    }
                                );
                        }
                        else if (rec.receiver !== sender.id && !storeMessage) {
                            // Insert the new message into the database
                            db.run('INSERT INTO messages (senderId, recId, message, read, sendTime) VALUES (?, ?, ?, ?, ?)', 
                                [sender.id, rec.id, encryptedMessage, 0, sendTime], 
                                function (err) {
                                    if (err) {
                                        console.error('Error saving message:', err);
                                        return;
                                    }
                        
                                    // Get the last inserted ID to update the specific message
                                    const insertedMessageId = this.lastID;
                        
                                    // Send message with sendTime to the receiver
                                    io.to(rec.socketId).emit('message', {
                                        user: username,          // Sender's username
                                        message: messageSent,     // Original (unencrypted) message to display
                                        date: sendTime,           // Include the stored sendTime
                                        store: storeMessage
                                    });
                        
                                    // Update the message to set 'read' to 0 and 'toDelete' to 1 for the just inserted message
                                    db.run('UPDATE messages SET read = 0, toDelete = 1 WHERE id = ?', 
                                        [insertedMessageId], 
                                        function (err) {
                                            if (err) {
                                                console.error('Error updating message read status:', err);
                                            } else {
                                                console.log(`Message marked for deletion for receiver: ${receiver}`);
                                            }
                                        });
                                });
                        }
                        else if (rec.receiver !== sender.id && storeMessage) {
                            // Insert the new message into the database
                            db.run('INSERT INTO messages (senderId, recId, message, read, sendTime) VALUES (?, ?, ?, ?, ?)', 
                                [sender.id, rec.id, encryptedMessage, 0, sendTime], 
                                function (err) {
                                    if (err) {
                                        console.error('Error saving message:', err);
                                        return;
                                    }
                        
                                    // Get the last inserted ID to update the specific message
                                    const insertedMessageId = this.lastID;
                        
                                    // Send message with sendTime to the receiver
                                    io.to(rec.socketId).emit('message', {
                                        user: username,          // Sender's username
                                        message: messageSent,     // Original (unencrypted) message to display
                                        date: sendTime,           // Include the stored sendTime
                                        store: storeMessage
                                    });
                        
                                    // Update the message to set 'read' to 0 and 'toDelete' to 1 for the just inserted message
                                    db.run(`
                                        UPDATE messages 
                                        SET read = 1 
                                        WHERE recId = ? AND senderId = ? 
                                          AND read = 0`,  // Only update unread messages
                                        [sender.id, rec.id],  // Use `rec.id` instead of `receiverResult.id`
                                        (err) => {
                                            if (err) {
                                                console.error('Error marking messages as read:', err);
                                            } else {
                                                console.log(`Messages marked as read between ${username} and ${receiver}`);
                                            }
                                        }
                                    );
                                    
                                });
                        }
                        else if (rec.receiver === sender.id && !storeMessage) {
                            
                            io.to(rec.socketId).emit('message', {
                                user: username,          // Sender's username
                                message: messageSent,     // Original (unencrypted) message to display
                                date: sendTime,            // Include the stored sendTime
                                store: storeMessage
                            });

                        }
                    }
                );
            });
        });
    });
    
    
    // socket.on('group message', ({ username, group, messageSent, storeMessage, sendTime }) => {
    //     // Fetch sender's ID
    //     db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, sender) => {
    //         if (err || !sender) {
    //             console.error("Sender not found or error:", err);
    //             return;
    //         }
    //         const senderId = sender.id;
    
    //         // Fetch accepted group members
    //         db.all(`
    //             SELECT invited AS recId 
    //             FROM groupInvite 
    //             WHERE groupId = ? AND accepted = 1`, [group], (err, members) => {
    //                 if (err) {
    //                     console.error("Error fetching group members:", err);
    //                     return;
    //                 }
    
    //                 members.forEach((member) => {
    //                     const recId = member.recId;
    
    //                     if (storeMessage) {
    //                         // Check if the recipient has `groupRec` in users table matching `group`
    //                         db.get(`SELECT id FROM users WHERE id = ? AND groupRec = ?`, [recId, group], (err, userInGroup) => {
    //                             if (err) {
    //                                 console.error("Error checking user's group:", err);
    //                                 return;
    //                             }
    
    //                             db.run(`
    //                                 INSERT INTO GroupMessages (senderId, RecId, message, read, sendTime, toDelete) 
    //                                 VALUES (?, ?, ?, ?, ?, ?)`,
    //                                 [
    //                                     senderId, recId, messageSent,
    //                                     userInGroup ? 1 : 0, // Set `read` to 1 if the recipient is in the group
    //                                     sendTime, 0 // `toDelete` set to 0 since the message is stored for group members
    //                                 ], (err) => {
    //                                     if (err) console.error("Error storing message:", err);
    //                                 }
    //                             );
    //                         });
    //                     } else {
    //                         // `storeMessage` is false; only store if recipient does not have the group assigned
    //                         db.get(`SELECT id FROM users WHERE id = ? AND groupRec = ?`, [recId, group], (err, userInGroup) => {
    //                             if (err) {
    //                                 console.error("Error checking user's group:", err);
    //                                 return;
    //                             }
    
    //                             if (!userInGroup) {
    //                                 // Store the message with `toDelete` set to 1 if the recipient is not in the group
    //                                 db.run(`
    //                                     INSERT INTO GroupMessages (senderId, RecId, message, read, sendTime, toDelete) 
    //                                     VALUES (?, ?, ?, ?, ?, ?)`,
    //                                     [
    //                                         senderId, recId, messageSent,
    //                                         0, sendTime, 1 // `read` = 0, `toDelete` = 1 since recipient lacks the group
    //                                     ], (err) => {
    //                                         if (err) console.error("Error setting toDelete:", err);
    //                                     }
    //                                 );
    //                             }
    //                             // If user is in the group (`userInGroup` exists), do not store the message.
    //                         });
    //                     }
    //                 });
    //             });
            
    //         socket.to(group).emit('send group message', { sender: username, groupOfMessage: group, message: messageSent, store: storeMessage, time: sendTime });
    //     });
    // });
    

// Handle requests for previous messages

socket.on('group message', ({ username, group, messageSent, storeMessage, sendTime }) => { 
    // Fetch sender's ID
    const encryptedMessage = encrypt(messageSent);
    // console.log(decrypt("mess", encryptedMessage));
    if (typeof messageSent === 'string') {
        console.log("string");
    }
    else console.log("not string");
    db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, sender) => {
        if (err || !sender) {
            console.error("Sender not found or error:", err);
            return;
        }
        const senderId = sender.id;

        // Fetch the group name from the groups table
        db.get(`SELECT name FROM groups WHERE id = ?`, [group], (err, groupInfo) => {
            if (err || !groupInfo) {
                console.error("Group not found or error:", err);
                return;
            }
            const groupName = groupInfo.name;

            // Fetch accepted group members
            db.all(`SELECT invited AS recId FROM groupInvite WHERE groupId = ? AND accepted = 1`, [group], (err, members) => {
                if (err) {
                    console.error("Error fetching group members:", err);
                    return;
                }

                members.forEach((member) => {
                    const recId = member.recId;
                     // Encrypt the message

                    if (storeMessage) {
                        // Check if the recipient has `groupRec` in users table matching `group`
                        db.get(`SELECT id FROM users WHERE id = ? AND groupRec = ?`, [recId, group], (err, userInGroup) => {
                            if (err) {
                                console.error("Error checking user's group:", err);
                                return;
                            }

                            // Store message in GroupMessages with proper read status
                            db.run(`INSERT INTO GroupMessages (senderId, RecId, message, read, sendTime, toDelete, groupId) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                                [
                                    senderId, recId, encryptedMessage,
                                    userInGroup ? 1 : 0, // Set `read` to 1 if the recipient is in the group
                                    sendTime, 0,
                                    group // `toDelete` set to 0 for group members
                                ], (err) => {
                                    if (err) console.error("Error storing message:", err);
                                });
                        });
                    } else {
                        // Only store if recipient does not have the group assigned
                        db.get(`SELECT id FROM users WHERE id = ? AND groupRec = ?`, [recId, group], (err, userInGroup) => {
                            if (err) {
                                console.error("Error checking user's group:", err);
                                return;
                            }

                            if (!userInGroup) {
                                // Store message with `toDelete` set to 1 for non-group members
                                db.run(`INSERT INTO GroupMessages (senderId, RecId, message, read, sendTime, toDelete, groupId) 
                                        VALUES (?, ?, ?, ?, ?, ?, ?)`,
                                    [
                                        senderId, recId, encryptedMessage,
                                        0, sendTime, 1,
                                        group // `read` = 0, `toDelete` = 1 since recipient lacks the group
                                    ], (err) => {
                                        if (err) console.error("Error setting toDelete:", err);
                                    });
                            }
                            // If user is in the group, do not store the message.
                        });
                    }
                });

                // Emit the message including the group name
                socket.to(group).emit('send group message', { 
                    sender: username, 
                    groupOfMessage: group, 
                    groupName: groupName, // Include the group name here
                    message: messageSent, // Use the original message for emitting
                    store: storeMessage, 
                    time: sendTime 
                });
            });
        });
    });
});

socket.on('requestGroupMessages', (groupId) => {
    // Step 1: Find the sender's user ID and username based on socketId
    db.get(`SELECT id, username FROM users WHERE socketId = ?`, [socket.id], (err, user) => {
        if (err) {
            console.error('Error finding sender ID:', err);
            socket.emit('error', 'Error finding sender ID');
            return;
        }

        if (!user) {
            socket.emit('error', 'Sender not found.');
            return;
        }

        const senderId = user.id;

        // Step 2: Update receiver to NULL and groupRec to the sent groupId
        db.run(`UPDATE users SET receiver = NULL, groupRec = ? WHERE id = ?`, [groupId, senderId], (err) => {
            if (err) {
                console.error('Error updating user info:', err);
                socket.emit('error', 'Error updating user info');
                return;
            }

            // Step 3: Retrieve the group avatar from the groups table
            db.get(`SELECT avatar, name FROM groups WHERE id = ?`, [groupId], (err, group) => {
                if (err) {
                    console.error('Error retrieving group data:', err);
                    socket.emit('error', 'Error retrieving group data');
                    return;
                }

                const groupAvatar = group?.avatar || null;
                const groupName = group.name;

                // Step 4: Retrieve group messages along with sender's name
                db.all(`
                    SELECT GroupMessages.id, GroupMessages.message, GroupMessages.sendTime, GroupMessages.read, GroupMessages.toDelete, 
                           users.username AS senderName
                    FROM GroupMessages
                    JOIN users ON GroupMessages.senderId = users.id
                    WHERE GroupMessages.RecId = ? AND GroupMessages.groupId = ?`, 
                [senderId, groupId], (err, messages) => {
                    if (err) {
                        console.error('Error retrieving group messages:', err);
                        socket.emit('error', 'Error retrieving group messages');
                        return;
                    }

                    // Format messages with decrypted content
                    const formattedMessages = messages.map(msg => {
                        try {
                            const decryptedMessage = decrypt(msg.message);
                            return {
                                message: decryptedMessage,
                                sendTime: msg.sendTime,
                                senderName: msg.senderName,
                                store: msg.toDelete
                            };
                        } catch (error) {
                            console.error('Decryption error for message:', msg.message, error);
                            return null;
                        }
                    }).filter(Boolean);

                    // Step 5: Count unread messages (read = 0) for the current RecId
                    db.get(`
                        SELECT COUNT(*) AS unreadGroupCount
                        FROM GroupMessages
                        WHERE RecId = ? AND groupId = ? AND read = 0`,
                    [senderId, groupId], (err, row) => {
                        if (err) {
                            console.error('Error counting unread group messages:', err);
                            socket.emit('error', 'Error counting unread group messages');
                            return;
                        }

                        const unreadGroupCount = row?.unreadGroupCount || 0;

                        // Step 6: Send messages, group info, and unread count to the client
                        socket.emit('groupMessages', { 
                            messages: formattedMessages, 
                            groupAvatar, 
                            groupName, 
                            groupId, 
                            unreadGroupCount // Include unread count here
                        });

                        // Step 7: Update unread messages (read = 0) to read (read = 1)
                        const unreadMessageIds = messages.filter(msg => msg.read === 0).map(msg => msg.id);
                        if (unreadMessageIds.length > 0) {
                            const placeholders = unreadMessageIds.map(() => '?').join(',');
                            db.run(`UPDATE GroupMessages SET read = 1 WHERE id IN (${placeholders})`, unreadMessageIds, (err) => {
                                if (err) {
                                    console.error('Error updating message read status:', err);
                                    socket.emit('error', 'Error updating message read status');
                                    return;
                                }
                            });
                        }

                        // Step 8: Delete messages marked with 'toDelete'
                        db.run(`DELETE FROM GroupMessages WHERE toDelete = 1 AND RecId = ? AND groupId = ?`, [senderId, groupId], (err) => {
                            if (err) {
                                console.error('Error deleting messages marked for deletion:', err);
                            }
                        });
                    });
                });
            });
        });
    });
});


    socket.on('sendMeMessages', (username, receiver) => {
        // Retrieve ID of the sender (username)
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, sender) => {
            if (err || !sender) {
                console.error('Error finding sender:', err);
                return;
            }

            // Retrieve ID, profileImage, and username of the receiver (receiver username)
            db.get('SELECT id, profileImage, username FROM users WHERE username = ?', [receiver], (err, receiverResult) => {
                if (err || !receiverResult) {
                    console.error('Error finding receiver:', err);
                    return;
                }

                // Update the 'receiver' column and set 'groupRec' to NULL in the 'users' table for the sender
                db.run('UPDATE users SET receiver = ?, groupRec = NULL WHERE id = ?', [receiverResult.id, sender.id], (err) => {
                    if (err) {
                        console.error('Error updating receiver or resetting groupRec for sender:', err);
                        return;
                    }
                    console.log(`Receiver updated and groupRec set to NULL for user ${username}`);

                    // Fetch messages between the sender and receiver, now including sendTime
                    db.all(`
                        SELECT messages.id, 
                            messages.message, 
                            messages.read, 
                            messages.sendTime, 
                            messages.toDelete,
                            sender.username AS senderUsername, 
                            receiver.username AS receiverUsername 
                        FROM messages 
                        JOIN users AS sender ON messages.senderId = sender.id 
                        JOIN users AS receiver ON messages.recId = receiver.id 
                        WHERE (messages.senderId = ? AND messages.recId = ?) 
                        OR (messages.senderId = ? AND messages.recId = ?)`,
                        [receiverResult.id, sender.id, sender.id, receiverResult.id],
                        (err, messages) => {
                            if (err) {
                                console.error('Error fetching messages:', err);
                                return;
                            }

                            // Decrypt each message and include sendTime
                            const decryptedMessages = messages.map(msg => {
                                try {
                                    return {
                                        id: msg.id,
                                        message: decrypt(msg.message),
                                        senderUsername: msg.senderUsername,
                                        receiverUsername: msg.receiverUsername,
                                        read: msg.read,
                                        time: msg.sendTime,
                                        toDelete: msg.toDelete
                                    };
                                } catch (decryptionError) {
                                    console.error('Error decrypting message:', decryptionError);
                                    return null;
                                }
                            }).filter(msg => msg !== null);

                            // Count unread messages where `recId` is `sender.id` and `senderId` is `receiverResult.id`
                            db.get(`
                                SELECT COUNT(*) AS unreadCount 
                                FROM messages 
                                WHERE recId = ? AND senderId = ? AND read = 0`,
                                [sender.id, receiverResult.id],
                                (err, row) => {
                                    if (err) {
                                        console.error('Error counting unread messages:', err);
                                        return;
                                    }

                                    const unreadCount = row.unreadCount;

                                    // Send decrypted messages, profile image, unread count, and receiver's username
                                    socket.emit('messagesResponse', {
                                        messages: decryptedMessages,
                                        profileImage: receiverResult.profileImage,
                                        unreadCount: unreadCount,
                                        receiverUsername: receiverResult.username  // Include receiver's username here
                                    });

                                    // Mark messages as read if the receiver (user) has seen them
                                    db.run(`
                                        UPDATE messages 
                                        SET read = 1 
                                        WHERE recId = ? AND senderId = ? AND read = 0`,
                                        [sender.id, receiverResult.id],
                                        (err) => {
                                            if (err) {
                                                console.error('Error marking messages as read:', err);
                                            } else {
                                                console.log(`Messages marked as read between ${username} and ${receiver}`);
                                            }
                                        }
                                    );

                                    // Delete messages marked with 'toDelete'
                                    const messagesToDelete = messages.filter(msg => msg.toDelete === 1).map(msg => msg.id);
                                    if (messagesToDelete.length > 0) {
                                        db.run(`DELETE FROM messages WHERE id IN (${messagesToDelete.join(',')})`, (err) => {
                                            if (err) {
                                                console.error('Error deleting messages:', err);
                                            } else {
                                                console.log('Messages with toDelete = 1 have been deleted:', messagesToDelete);
                                            }
                                        });
                                    }
                                }
                            );
                        }
                    );
                });
            });
        });
    });



    socket.on('typing', (isTyping, receiver) => {
        console.log(receiver);
    
        // Find sender's username by socket ID
        db.get('SELECT username FROM users WHERE socketId = ?', [socket.id], (err, sender) => {
            if (err || !sender) {
                console.error('Sender not found for socket:', socket.id);
                return;
            }
    
            // Find receiver's socket ID by username
            db.get('SELECT socketId FROM users WHERE username = ?', [receiver], (err, rec) => {
                if (err || !rec) {
                    console.error('Receiver not found:', receiver);
                    return;
                }
    
                // Emit the typing event to the receiver, with the sender's username
                io.to(rec.socketId).emit('userTyping', { isTyping, sender: sender.username });
            });
        });
    });
    
    socket.on('login', (username) => {
        // Fetch user details by username
        db.get('SELECT id, profileImage FROM users WHERE username = ?', [username], (err, user) => {
            if (err || !user) {
                console.error('User not found:', username);
                return;
            }
    
            // Update the user's socket ID in the database
            db.run('UPDATE users SET socketId = ? WHERE id = ?', [socket.id, user.id], (err) => {
                if (err) {
                    console.error('Error updating socket ID:', err);
                    return;
                }
    
                // Emit the friends list to the logged-in user
                fetchFriends(user.id, (friends) => {
                    io.to(socket.id).emit('friendsList', friends);
    
                    // Notify each friend about the user's online status
                    friends.forEach(friend => {
                        if (friend.socketId) {
                            fetchFriends(friend.id, (updatedFriendsList) => {
                                // Notify the friend about their updated friend list
                                io.to(friend.socketId).emit('friendsList', updatedFriendsList);
                            });
                        }
                    });
    
                    // Notify all friends that the user has logged in (broadcast)
                    friends.forEach(friend => {
                        if (friend.socketId) {
                            io.to(friend.socketId).emit('friendOnline', { id: user.id, username: username });
                        }
                    });
                });
    
                // Emit user info (including profile image if available) to the user
                db.get('SELECT id, profileImage FROM users WHERE socketId = ?', [socket.id], (err, updatedUser) => {
                    if (err || !updatedUser) {
                        console.error('Updated user not found:', err);
                        return;
                    }
    
                    io.to(socket.id).emit('user info', {
                        id: updatedUser.id,
                        profileImage: updatedUser.profileImage || null
                    });
    
                    // Emit pending friend invitations
                    db.all(`
                        SELECT u.username, f.inviting 
                        FROM friends f
                        JOIN users u ON f.inviting = u.id
                        WHERE f.invited = ? AND f.accepted = 0
                    `, [updatedUser.id], (err, rows) => {
                        if (err) {
                            console.error('Error fetching invitations:', err);
                            return;
                        }
    
                        const pendingInvitations = rows.map(row => ({
                            username: row.username,
                            invitingId: row.inviting
                        }));
    
                        io.to(socket.id).emit('pendingInvitations', pendingInvitations);
                    });
    
                    // Emit unread message counts
                    db.all(`
                        SELECT senderId, COUNT(*) AS unreadCount 
                        FROM messages 
                        WHERE recId = ? AND read = 0 
                        GROUP BY senderId
                    `, [updatedUser.id], (err, unreadCounts) => {
                        if (err) {
                            console.error('Error fetching unread messages count:', err);
                            return;
                        }
    
                        const unreadWithUsernames = unreadCounts.map(count => {
                            return new Promise((resolve) => {
                                db.get('SELECT username FROM users WHERE id = ?', [count.senderId], (err, sender) => {
                                    if (err || !sender) {
                                        resolve({ username: null, unreadCount: count.unreadCount });
                                    } else {
                                        resolve({ username: sender.username, unreadCount: count.unreadCount });
                                    }
                                });
                            });
                        });
    
                        // Emit unread message counts after resolving all usernames
                        Promise.all(unreadWithUsernames).then(results => {
                            io.to(socket.id).emit('unread message counts', results);
                        });
                    });
    
                    // Emit pending group invitations
                    db.all(`
                        SELECT u.username AS invitingUsername, gi.groupId, gi.groupName 
                        FROM groupInvite gi
                        JOIN users u ON gi.inviting = u.id
                        WHERE gi.invited = ? AND gi.accepted = 0
                    `, [updatedUser.id], (err, groupInvites) => {
                        if (err) {
                            console.error('Error fetching group invitations:', err);
                            return;
                        }
    
                        const pendingGroupInvites = groupInvites.map(invite => ({
                            invitingUsername: invite.invitingUsername,
                            groupId: invite.groupId,
                            groupName: invite.groupName
                        }));
    
                        io.to(socket.id).emit('groupInvites', pendingGroupInvites);
                    });
    
                    // Emit accepted group invitations
                    db.all(`
                        SELECT g.id AS groupId, g.name AS groupName, g.avatar AS groupAvatar,
                            CASE WHEN EXISTS (
                                SELECT 1 
                                FROM groupInvite gi_inner
                                JOIN users u ON gi_inner.invited = u.id 
                                WHERE gi_inner.groupId = g.id 
                                  AND gi_inner.accepted = 1 
                                  AND u.socketId IS NOT NULL 
                                  AND u.id != ?  -- Exclude the current user
                            ) THEN 1 ELSE 0 END AS online
                        FROM groupInvite gi
                        JOIN groups g ON gi.groupId = g.id
                        WHERE gi.invited = ? AND gi.accepted = 1
                    `, [updatedUser.id, updatedUser.id], (err, groupInvites) => {
                        if (err) {
                            console.error('Error fetching accepted group invitations:', err);
                            return;
                        }
                    
                        const acceptedGroupInvites = groupInvites.map(invite => ({
                            groupId: invite.groupId,
                            groupName: invite.groupName,
                            groupAvatar: invite.groupAvatar || null,
                            online: invite.online
                        }));
                    
                        io.to(socket.id).emit('acceptedGroupInvites', acceptedGroupInvites);
                    });
                    
                    // User joins accepted groups (broadcast to group members)
                    db.all(`
                        SELECT g.id AS groupId, g.name AS groupName, g.avatar AS groupAvatar
                        FROM groupInvite gi
                        JOIN groups g ON gi.groupId = g.id
                        WHERE gi.invited = ? AND gi.accepted = 1
                    `, [updatedUser.id], (err, groupInvites) => {
                        if (err) {
                            console.error('Error fetching accepted groups:', err);
                            return;
                        }
    
                        const myGroups = groupInvites.map(invite => ({
                            groupId: invite.groupId,
                            groupName: invite.groupName,
                            groupAvatar: invite.groupAvatar || null
                        }));
    
                        // Join each group room and broadcast to all group members
                        myGroups.forEach(group => {
                            socket.join(`${group.groupId}`);
                            console.log(`User joined group room: ${group.groupId}`);
                            
                            // Broadcast to all group members about the user joining
                            io.to(`${group.groupId}`).emit('userJoinedGroup', {
                                userId: updatedUser.id,
                                username: updatedUser.username,
                                groupId: group.groupId,
                                groupName: group.groupName
                            });
                        });
    
                        io.to(socket.id).emit('joinedGroups', myGroups);
                    });
                    // Emit unread group message counts
                    db.all(`
                        SELECT g.id AS groupId, g.name AS groupName, COUNT(gm.id) AS unreadCount
                        FROM GroupMessages gm
                        JOIN groups g ON gm.groupId = g.id
                        WHERE gm.RecId = ? AND gm.read = 0
                        GROUP BY g.id
                    `, [user.id], (err, unreadGroups) => {
                        if (err) {
                            console.error('Error fetching unread group messages count:', err);
                            return;
                        }

                        // Structure the data to include group ID, group name, and unread message count
                        const unreadGroupCounts = unreadGroups.map(group => ({
                            groupId: group.groupId,
                            groupName: group.groupName,
                            unreadCount: group.unreadCount
                        }));

                        // Emit the unread group message counts to the user
                        io.to(socket.id).emit('unreadGroupMessageCounts', unreadGroupCounts);
                    });

                });
            });
        });
    });
    
    
    socket.on('give me friends to group', (username) => { 
        db.get('SELECT id, profileImage FROM users WHERE username = ?', [username], (err, user) => {
            if (err || !user) {
                console.error('User not found:', username);
                return;
            }
    
            // Update the user's socket ID
            
                
                
                // Emit the friends list to the logged-in user
                fetchFriends(user.id, (friends) => {
                    io.to(socket.id).emit('friendsToGroup', friends); // Send list to logged-in user
    
                    // Notify each friend about their updated friend list
                    
                });
    
                // Fetch the user again after socketId is updated
                
            
        });
    });
    
    
    
    
    
    socket.on('findUsers', async (searchUser) => {
        console.log("Searching for user:", searchUser);
        try {
            const founded = await findBlocked(searchUser, socket.id);
            socket.emit('foundUsers', founded);
        } catch (error) {
            console.error("Error finding users:", error);
            socket.emit('searchError', { message: 'Failed to find users.' });
        }
    });
    
    async function areUsersBlocked(invitingId, invitedId) {
        return new Promise((resolve, reject) => {
            db.get('SELECT * FROM blocked WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)',
                [invitingId, invitedId, invitedId, invitingId],
                (err, row) => {
                    if (err) {
                        reject('Error checking block status');
                    } else if (row) {
                        reject('Blocked: One user has blocked the other');
                        socket.emit('inviteProcessed');
                    } else {
                        resolve(true); // No block found
                        socket.emit('inviteProcessed');
                    }
                });
        });
    }
    socket.on('invite', async (invitedUser) => {
        console.log("Processing invite...");

        // Find the ID and username of the inviting user
        db.get('SELECT id, username FROM users WHERE socketId = ?', [socket.id], (err, inviting) => {
            if (err || !inviting) {
                console.error('Error finding inviting user:', err);
                return;
            }

            // Find the ID and socketId of the invited user
            db.get('SELECT id, socketId FROM users WHERE username = ?', [invitedUser], async (err, invited) => {
                if (err || !invited) {
                    console.error('Error finding invited user:', err);
                    return;
                }

                // Check if either user has blocked the other
                try {
                    await areUsersBlocked(inviting.id, invited.id);
                } catch (error) {
                    console.error(error);
                    socket.emit('blockError', { message: 'You cannot invite this user.' });
                    return; // Exit if blocked
                }

                // Check if the invited user has already been invited
                db.get('SELECT * FROM friends WHERE inviting = ? AND invited = ?', [inviting.id, invited.id], (err, existingInvite) => {
                    if (err) {
                        console.error('Error checking invitation status:', err);
                        return;
                    }

                    if (existingInvite) {
                        socket.emit('inviteError', { message: 'Invitation already sent.' });
                        return; // Exit if already invited
                    }
                    console.log("insert");
                    // Insert into the friends table with accepted set to 0 (pending)
                    db.run('INSERT INTO friends (inviting, invited, accepted) VALUES (?, ?, 0)', [inviting.id, invited.id], (err) => {
                        if (err) {
                            console.error('Error inserting into friends table:', err);
                        } else {
                            console.log(`User ${inviting.username} invited ${invitedUser}`);

                            // Send invitation to the invited user using their socketId
                            if (invited.socketId) {
                                io.to(invited.socketId).emit('send invitation', {
                                    from: inviting.username,
                                    id: inviting.id,
                                    message: `You have received an invitation from user ${inviting.username}.`
                                });
                            } else {
                                console.error('Invited user does not have a valid socketId.');
                            }

                            // Emit a custom event to signal that the invite is processed
                            console.log('check inviteProcessed')
                            
                        }
                    });
                });
            });
        });
    });
    
    
    
    socket.on('confirm group', ({ decision, invitingName }) => {
        // Find the invited user's id based on their socket ID
        db.get(`SELECT id FROM users WHERE socketId = ?`, [socket.id], (err, invitedUser) => {
            if (err) {
                console.error('Error finding user by socketId:', err);
                return;
            }
    
            if (!invitedUser) {
                console.log('User not found.');
                return;
            }
    
            const invitedUserId = invitedUser.id;
    
            // Find the invitation by the invited user's id and groupId
            db.get(`SELECT * FROM groupInvite WHERE invited = ? AND groupId = ?`, 
                [invitedUserId, invitingName], (err, row) => {
                if (err) {
                    console.error('Error finding group invitation:', err);
                    return;
                }
    
                if (!row) {
                    console.log('Invitation not found.');
                    return;
                }
    
                if (decision === true) {
                    socket.join(invitingName);
    
                    // If decision is true, update the invitation status to accepted
                    db.run(`UPDATE groupInvite SET accepted = 1 WHERE id = ?`, [row.id], (err) => {
                        if (err) {
                            console.error('Error updating invitation status:', err);
                            return;
                        }
    
                        // Get group details
                        db.get(`SELECT name, avatar FROM groups WHERE id = ?`, [invitingName], (err, group) => {
                            if (err) {
                                console.error('Error retrieving group details:', err);
                                return;
                            }
    
                            // Check if any group members have a non-null socketId
                            db.get(`SELECT COUNT(*) as onlineCount
                                    FROM users u
                                    JOIN groupInvite gi ON gi.invited = u.id
                                    WHERE gi.groupId = ?
                                    AND gi.accepted = 1
                                    AND u.socketId IS NOT NULL`, 
                                    [invitingName], (err, result) => {
                                if (err) {
                                    console.error('Error checking group member online status:', err);
                                    return;
                                }
    
                                const isOnline = result.onlineCount > 1 ? 1 : 0;  // Set 1 if any user is online
    
                                // Emit group details to the user who accepted the invite
                                socket.emit('group confirmed', {
                                    groupId: invitingName,
                                    groupName: group.name,
                                    groupAvatar: group.avatar,
                                    lineStatus: isOnline  // Add lineStatus to the emitted data
                                });
    
                                // Send the same group details to all accepted users in the group
                                db.all(`SELECT u.socketId 
                                    FROM users u 
                                    JOIN groupInvite gi ON gi.invited = u.id 
                                    WHERE gi.groupId = ? 
                                    AND gi.accepted = 1 
                                    AND gi.invited <> ?`,   // Exclude the current user
                                    [invitingName, invitedUserId], 
                                    (err, acceptedUsers) => {
                                    if (err) {
                                        console.error('Error retrieving accepted users:', err);
                                        return;
                                    }
    
                                    acceptedUsers.forEach(user => {
                                        // Send group details to each accepted user
                                        io.to(user.socketId).emit('group confirmed', {
                                            groupId: invitingName,
                                            groupName: group.name,
                                            groupAvatar: group.avatar,
                                            lineStatus: isOnline  // Include lineStatus
                                        });
                                    });
                                });
                            });
                        });
                    });
                } else {
                    // If decision is false, delete the invitation row
                    db.run(`DELETE FROM groupInvite WHERE id = ?`, [row.id], (err) => {
                        if (err) {
                            console.error('Error deleting group invitation:', err);
                        }
                    });
                }
            });
        });
    });
    
    socket.on('joinGroup', (username, groupId) => {
        // Retrieve ID of the sender (username)
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, sender) => {
            if (err || !sender) {
                console.error('Error finding sender:', err);
                return;
            }
    
            // Update the 'receiver' column to NULL and set 'groupRec' to the provided groupId
            db.run('UPDATE users SET receiver = NULL, groupRec = ? WHERE id = ?', [groupId, sender.id], (err) => {
                if (err) {
                    console.error('Error updating receiver and groupRec for sender:', err);
                    return;
                }
                console.log(`Receiver set to NULL and groupRec updated to ${groupId} for user ${username}`);
            });
        });
    });
    // When the client sends a group ID to delete the invite
    socket.on('quit group', (groupId) => {
        // Step 1: Remove the user from the socket room
        socket.leave(groupId);
    
        // Step 2: Delete the user's invite from the groupInvite table
        db.run(`
            DELETE FROM groupInvite 
            WHERE groupId = ? AND invited = (
                SELECT id FROM users WHERE socketId = ?
            )
        `, [groupId, socket.id], (err) => {
            if (err) {
                console.error('Error deleting group invite:', err);
                return;
            }
    
            // Step 3: After deletion, count remaining online users excluding the current user
            db.all(`
                SELECT u.socketId
                FROM groupInvite gi
                JOIN users u ON gi.invited = u.id
                WHERE gi.groupId = ? AND gi.accepted = 1 
                AND u.socketId IS NOT NULL
                AND u.socketId != ?
            `, [groupId, socket.id], (err, rows) => {
                if (err) {
                    console.error('Error checking for online group members:', err);
                    return;
                }
    
                // Step 4: Notify all remaining online users if there is at least one online
                if (rows && rows.length > 0) {
                    rows.forEach(row => {
                        io.to(row.socketId).emit('user quit group', { groupId });
                    });
                }
            });
        });
    });
    
    

    socket.on('group selected', (username, group) => {
        // Retrieve ID of the sender (username)
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, sender) => {
            if (err || !sender) {
                console.error('Error finding sender:', err);
                return;
            }
    
            // Update the 'receiver' column to NULL and set 'groupRec' to the provided groupId
            db.run('UPDATE users SET receiver = NULL, groupRec = ? WHERE id = ?', [group, sender.id], (err) => {
                if (err) {
                    console.error('Error updating receiver and groupRec for sender:', err);
                    return;
                }
                console.log(`Receiver set to NULL and groupRec updated to ${group} for user ${username}`);
            });
        });
    });
        
    
    socket.on('confirm invite', ({ decision, invitingName }) => {
        // Find the invited user's info (current user)
        db.get('SELECT id, username, profileImage FROM users WHERE socketId = ?', [socket.id], (err, invited) => {
            if (err || !invited) {
                console.error('Invited user not found:', err);
                return;
            }

            const invitedId = invited.id;
            const invitedName = invited.username;
            const invitedImage = invited.profileImage;

            // Find the inviting user's info based on their username (invitingName)
            db.get('SELECT id, socketId, profileImage FROM users WHERE username = ?', [invitingName], (err, inviting) => {
                if (err || !inviting) {
                    console.error('Inviting user not found:', err);
                    return;
                }

                const invitingId = inviting.id;
                const invitingSocketId = inviting.socketId;
                const invitingImage = inviting.profileImage;

                if (decision) {  // If the invitation is accepted
                    db.run('UPDATE friends SET accepted = 1 WHERE inviting = ? AND invited = ?', [invitingId, invitedId], function (err) {
                        if (err) {
                            console.error('Error updating friends table:', err);
                        } else if (this.changes === 0) {
                            console.log('No rows updated. Check if inviting and invited IDs are correct.');
                        } else {
                            console.log(`Invitation accepted by user ${invitedId}`);

                            // Fetch and send the friends list for both users
                            const fetchFriends = (userId, callback) => {
                                const query = `
                                    SELECT 
                                        CASE 
                                            WHEN f.inviting = ? THEN u2.username
                                            ELSE u1.username
                                        END AS name,
                                        CASE 
                                            WHEN f.inviting = ? THEN u2.profileImage
                                            ELSE u1.profileImage
                                        END AS image,
                                        CASE 
                                            WHEN f.inviting = ? THEN u2.socketId
                                            ELSE u1.socketId
                                        END AS friendSocketId,
                                        CASE 
                                            WHEN (CASE WHEN f.inviting = ? THEN u2.socketId ELSE u1.socketId END) IS NOT NULL
                                            THEN 1 ELSE 0
                                        END AS online
                                    FROM friends f
                                    JOIN users u1 ON f.inviting = u1.id
                                    JOIN users u2 ON f.invited = u2.id
                                    WHERE (f.inviting = ? OR f.invited = ?) AND f.accepted = 1
                                `;
                                db.all(query, [userId, userId, userId, userId, userId, userId], (err, friends) => {
                                    if (err) {
                                        console.error('Error fetching friends:', err);
                                    }
                                    callback(friends);
                                });
                            };

                            // Send the invited user's updated friends list
                            fetchFriends(invitedId, (invitedFriends) => {
                                socket.emit('friendsList', invitedFriends);
                            });

                            // Send the inviting user's updated friends list
                            fetchFriends(invitingId, (invitingFriends) => {
                                io.to(invitingSocketId).emit('friendsList', invitingFriends);
                            });

                            // Optionally, confirm the invitation to both parties
                            io.to(invitingSocketId).emit('invitationConfirmed', {
                                invitedName: invitedName,
                                invitedImage: invitedImage
                            });
                            socket.emit('invitationConfirmed', {
                                invitingName: invitingName,
                                invitingImage: invitingImage
                            });
                        }
                    });
                } else {  // If the invitation is rejected
                    db.run('DELETE FROM friends WHERE inviting = ? AND invited = ?', [invitingId, invitedId], (err) => {
                        if (err) {
                            console.error('Error deleting from friends table:', err);
                        } else {
                            console.log(`Invitation rejected by user ${invitedId}`);
                        }
                    });
                }
            });
        });
    });
    function updateSocketId(userId, socketId) {
        db.run('UPDATE users SET socketId = ? WHERE id = ?', [socketId, userId], (err) => {
            if (err) {
                console.error('Error updating socketId:', err);
            } else {
                console.log(`SocketId updated for userId ${userId}`);
            }
        });
    }
    
    
    
    socket.on('receiver', (receiver) => {
        const currentSocketId = socket.id;
    
        // Find the sender (current user) based on the socket ID
        db.get(`SELECT id FROM users WHERE socketId = ?`, [currentSocketId], (err, senderRow) => {
            if (err || !senderRow) {
                console.error('Error finding sender:', err);
                return;
            }
    
            const senderId = senderRow.id;
    
            // Find the receiver's ID based on the receiver's username
            db.get(`SELECT id FROM users WHERE username = ?`, [receiver], (err, receiverRow) => {
                if (err || !receiverRow) {
                    console.error('Error finding receiver:', err);
                    return;
                }
    
                const receiverId = receiverRow.id;
    
                // Update the sender's receiver field
                db.run(`UPDATE users SET receiver = ? WHERE id = ?`, [receiverId, senderId], (err) => {
                    if (err) {
                        console.error('Error updating receiver for sender:', err);
                    } else {
                        console.log('Receiver set successfully for sender with socketId:', currentSocketId);
                    }
                });
            });
        });
    });
    // socket.on('message', function(message) {
    //     // Save the binary data to a file
    //     fs.writeFile('uploaded_image.jpg', message, function(err) {
    //         if (err) throw err;
    //         console.log('The image has been saved!');
    
    //         // Broadcast the image to all users
    //         io.emit('newImage', message);  // Emit with 'newImage' event
    //     });
    // });
    const fs = require('fs');
const path = require('path'); // Ensure this is imported

socket.on('uploadImage', ({ imageData, fileType }) => {
    if (!fileType) {
        console.error('No file type provided!');
        return;
    }

    // Extract the file extension from fileType
    const extension = fileType.split('/')[1]; // This will extract 'png', 'jpeg', etc.

    // Ensure extension is valid before proceeding
    const validExtensions = ['jpeg', 'jpg', 'png', 'gif', 'bmp', 'svg', 'webp'];
    if (!validExtensions.includes(extension)) {
        console.error('Unsupported file type:', extension);
        return;
    }

    const uniqueFileName = `uploaded_image_${socket.id}_${Date.now()}.${extension}`;
    const uploadsDir = path.join(__dirname, 'uploads'); // Correctly join the uploads directory path
    const filePath = path.join(uploadsDir, uniqueFileName); // Correctly create the full path to save the image

    // Decode the base64 data
    const base64Data = imageData; // Already in base64 format from Data URL

    // Save the binary image data to a file
    fs.writeFile(filePath, base64Data, 'base64', (err) => {
        if (err) {
            console.error('Error saving the image:', err);
            return;
        }
        console.log('Image saved successfully:', filePath);

        // Update user's profile image in the database
        const relativePath = `/uploads/${uniqueFileName}`; // Use relative path for database
        db.run(`UPDATE users SET profileImage = ? WHERE socketId = ?`, [relativePath, socket.id], (err) => {
            if (err) {
                console.error('Error updating profile image:', err);
                return;
            }

            // Broadcast the new image to all users
            //io.emit('newImage', relativePath);
            socket.emit("avatar", relativePath);
        });
    });
});
// let isCreatingGroup = false; // Add a flag to track group creation state

// socket.on('createGroup', ({ groupName, invited, username }) => {
//     if (isCreatingGroup) {
//         console.log("Group creation in progress, please wait.");
//         return; // Prevent further calls if a group is already being created
//     }
    
//     isCreatingGroup = true; // Set the flag to true when starting the group creation process

//     // Prepare SQL query and values
//     let findUsersSQL;
//     let queryValues;

//     if (invited.length > 0) {
//         const placeholders = invited.map(() => '?').join(',');
//         findUsersSQL = `SELECT id, username, socketId FROM users WHERE username IN (${placeholders}, ?)`;
//         queryValues = [...invited, username];
//     } else {
//         findUsersSQL = `SELECT id, username, socketId FROM users WHERE username = ?`;
//         queryValues = [username];
//     }

//     console.log("Fetching user IDs for invited users and creator.");

//     db.all(findUsersSQL, queryValues, (err, rows) => {
//         isCreatingGroup = false; // Reset the flag at the end of the operation

//         if (err) {
//             console.error("Error fetching user IDs:", err);
//             return;
//         }

//         // User ID mapping
//         const userIds = {};
//         const socketIds = {};

//         rows.forEach(row => {
//             userIds[row.username] = row.id;
//             socketIds[row.username] = row.socketId;
//         });

//         console.log("User IDs fetched: ", userIds);

//         if (!userIds[username]) {
//             console.error("Creator not found in users table.");
//             return;
//         }

//         const allUserIds = [userIds[username], ...invited.map(user => userIds[user])];
        
//         if (allUserIds.length > 1) {
//             const placeholders = allUserIds.map(() => '?').join(',');
//             const blockCheckSQL = `SELECT * FROM blocked WHERE 
//                 (blocker IN (${placeholders}) AND blocked IN (${placeholders})) 
//                 OR (blocked IN (${placeholders}) AND blocker IN (${placeholders}))`;

//             console.log("Checking for block relationships.");

//             db.all(blockCheckSQL, [...allUserIds, ...allUserIds], (err, blockRows) => {
//                 if (err) {
//                     console.error("Error checking block status:", err);
//                     return;
//                 }

//                 const blockedUsers = new Set();
//                 blockRows.forEach(blockRow => {
//                     blockedUsers.add(blockRow.blocker);
//                     blockedUsers.add(blockRow.blocked);
//                 });

//                 console.log("Blocked users: ", blockedUsers);

//                 const validInvitedUsers = invited.filter(user => !blockedUsers.has(userIds[user]));
//                 console.log("Valid invited users after block filter: ", validInvitedUsers);

//                 createGroup(validInvitedUsers);
//             });
//         } else {
//             console.log("No invited users or block-check not needed, proceeding to group creation.");
//             createGroup(invited);
//         }

//         // Define the createGroup function
//         function createGroup(validInvitedUsers) {
//             if (!validInvitedUsers || validInvitedUsers.length === 0) {
//                 console.log("No valid invited users to add, only creating the group for the creator.");
//             }

//             const insertGroupSQL = `INSERT INTO groups (creator, name) VALUES (?, ?)`;
//             db.run(insertGroupSQL, [userIds[username], groupName], function(err) {
//                 if (err) {
//                     console.error("Error inserting group:", err);
//                     return;
//                 }

//                 const groupId = this.lastID;

//                 console.log("Group created with ID: ", groupId);

//                 const insertInviteSQL = `INSERT INTO groupInvite (inviting, invited, groupId, groupName, accepted) VALUES (?, ?, ?, ?, ?)`;

//                 validInvitedUsers.forEach(invitedUser => {
//                     db.run(insertInviteSQL, [userIds[username], userIds[invitedUser], groupId, groupName, 0], err => {
//                         if (err) {
//                             console.error(`Error inviting user ${invitedUser}:`, err);
//                         } else {
//                             const invitedSocketId = socketIds[invitedUser];
//                             if (invitedSocketId) {
//                                 io.to(invitedSocketId).emit('groupInvite', {
//                                     groupId,
//                                     groupName,
//                                     creator: username
//                                 });
//                                 console.log(`Invite sent to ${invitedUser}.`);
//                             }
//                         }
//                     });
//                 });

//                 db.run(insertInviteSQL, [userIds[username], userIds[username], groupId, groupName, 1], err => {
//                     if (err) {
//                         console.error("Error inserting creator's invite:", err);
//                     }
//                 });

//                 socket.emit('groupCreated', { groupId, groupName });
//             });
//         }
//     });
// });

let isCreatingGroup = false; // Add a flag to track group creation state

// Store the group creation status per user or socket
const groupCreationStatus = new Map();  // A Map to track group creation status per socket ID

socket.on('createGroup', ({ groupName, invited, username, avatar }) => { 
    if (groupCreationStatus.get(socket.id)) {
        console.log("Group creation already in progress, ignoring duplicate request.");
        return;
    }

    groupCreationStatus.set(socket.id, true);
    console.log(groupName, invited, username, avatar);

    const extension = avatar?.fileType?.split('/')[1];
    const validExtensions = ['jpeg', 'jpg', 'png', 'gif', 'bmp', 'svg', 'webp'];
    let relativePath = null;

    if (!avatar || !validExtensions.includes(extension)) {
        console.error('No valid file type provided! Setting avatar to null.');
        avatar = null; // Set avatar to null if invalid
    }

    if (avatar) {
        const uniqueFileName = `uploaded_image_${socket.id}_${Date.now()}.${extension}`;
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, uniqueFileName);
        const base64Data = avatar.imageData;

        fs.writeFile(filePath, base64Data, 'base64', (err) => {
            if (err) {
                console.error('Error saving the image:', err);
                return;
            }
            console.log('Image saved successfully:', filePath);
            relativePath = `/uploads/${uniqueFileName}`;
        });
    } else {
        console.log('No valid avatar provided. Proceeding without an avatar.');
    }

    let findUsersSQL;
    let queryValues;

    if (invited.length > 0) {
        const placeholders = invited.map(() => '?').join(',');
        findUsersSQL = `SELECT id, username, socketId FROM users WHERE username IN (${placeholders}, ?)`;
        queryValues = [...invited, username];
    } else {
        findUsersSQL = `SELECT id, username, socketId FROM users WHERE username = ?`;
        queryValues = [username];
    }

    console.log("Fetching user IDs for invited users and creator.");
    const userIds = {};
    const socketIds = {};

    db.all(findUsersSQL, queryValues, (err, rows) => {
        if (err) {
            console.error("Error fetching user IDs:", err);
            groupCreationStatus.delete(socket.id);  // Reset flag in case of error
            return;
        }

        rows.forEach(row => {
            userIds[row.username] = row.id;
            socketIds[row.username] = row.socketId;
        });

        console.log("User IDs fetched: ", userIds);

        if (!userIds[username]) {
            console.error("Creator not found in users table.");
            groupCreationStatus.delete(socket.id);  // Reset flag in case of error
            return;
        }

        const allUserIds = [userIds[username], ...invited.map(user => userIds[user])];

        if (allUserIds.length > 1) {
            const placeholders = allUserIds.map(() => '?').join(',');
            const blockCheckSQL = `SELECT blocker, blocked FROM blocked WHERE 
                blocker IN (${placeholders}) OR blocked IN (${placeholders})`;

            console.log("Checking for block relationships.");

            db.all(blockCheckSQL, [...allUserIds, ...allUserIds], (err, blockRows) => {
                if (err) {
                    console.error("Error checking block status:", err);
                    groupCreationStatus.delete(socket.id);  // Reset flag in case of error
                    return;
                }

                const blockedUsers = new Map();
                blockRows.forEach(blockRow => {
                    if (!blockedUsers.has(blockRow.blocker)) {
                        blockedUsers.set(blockRow.blocker, new Set());
                    }
                    blockedUsers.get(blockRow.blocker).add(blockRow.blocked);
                });

                console.log("Blocked users map: ", blockedUsers);

                const validInvitedUsers = invited.filter(user => {
                    const invitedUserId = userIds[user]; // Get the ID for the invited user
                    const blockerId = userIds[username]; // Get the ID for the blocker (the creator)
                
                    // Debugging output
                    console.log(`Checking user ${user} (ID: ${invitedUserId}) against blocker ${username} (ID: ${blockerId})`);
                
                    // Ensure both IDs are valid
                    if (invitedUserId && blockerId) {
                        // Check if the blocker has blocked this invited user
                        if (blockedUsers.has(blockerId)) {
                            const isBlockedByBlocker = blockedUsers.get(blockerId).has(invitedUserId);
                            console.log(`User ${user} is blocked by blocker ${username}: ${isBlockedByBlocker}`);
                
                            // Exclude the user if they are blocked by the blocker
                            if (isBlockedByBlocker) return false;
                        }
                
                        // Check if the invited user is blocked by any other invited users
                        for (const otherUser of invited) {
                            if (otherUser !== user) { // Skip self-comparison
                                const otherUserId = userIds[otherUser];
                
                                // Check if this user has blocked the other invited user
                                if (blockedUsers.has(invitedUserId) && blockedUsers.get(invitedUserId).has(otherUserId)) {
                                    console.log(`User ${user} is blocked by invited user ${otherUser}`);
                                    return false; // Exclude this user if blocked by another invited user
                                }
                            }
                        }
                    }
                
                    // Include the user if they are not blocked by the blocker or other invited users
                    return true; 
                });
                
                console.log("Valid invited users after block filter: ", validInvitedUsers);
                
                console.log("Valid invited users after block filter: ", validInvitedUsers);
                
                console.log("Valid invited users after block filter: ", validInvitedUsers);
                
                
                console.log("Valid invited users after block filter: ", validInvitedUsers);
                
                console.log("Valid invited users after block filter: ", validInvitedUsers);

                createGroup(validInvitedUsers, relativePath, userIds); // Pass userIds to createGroup
            });
        } else {
            console.log("No invited users or block-check not needed, proceeding to group creation.");
            createGroup(invited, relativePath, userIds); // Pass userIds to createGroup
        }
    });

    function createGroup(validInvitedUsers, relativePath, userIds) {
        if (!validInvitedUsers || validInvitedUsers.length === 0) {
            console.log("No valid invited users to add, only creating the group for the creator.");
        }

        const insertGroupSQL = `INSERT INTO groups (creator, name, avatar) VALUES (?, ?, ?)`;
        db.run(insertGroupSQL, [userIds[username], groupName, relativePath], function (err) {
            if (err) {
                console.error("Error inserting group:", err);
                groupCreationStatus.delete(socket.id);  // Reset flag in case of error
                return;
            }

            const groupId = this.lastID;
            console.log("Group created with ID: ", groupId);

            const insertInviteSQL = `INSERT INTO groupInvite (inviting, invited, groupId, groupName, accepted) VALUES (?, ?, ?, ?, ?)`;

            validInvitedUsers.forEach(invitedUser => {
                db.run(insertInviteSQL, [userIds[username], userIds[invitedUser], groupId, groupName, 0], err => {
                    if (err) {
                        console.error(`Error inviting user ${invitedUser}:`, err);
                    } else {
                        const invitedSocketId = socketIds[invitedUser];
                        if (invitedSocketId) {
                            io.to(invitedSocketId).emit('groupInvite', {
                                groupId,
                                groupName,
                                creator: username
                            });
                            console.log(`Invite sent to ${invitedUser}.`);
                        }
                    }
                });
            });

            db.run(insertInviteSQL, [userIds[username], userIds[username], groupId, groupName, 1], err => {
                if (err) {
                    console.error("Error inserting creator's invite:", err);
                } else {
                    socket.join(`${groupId}`);
                    console.log(`Creator ${username} joined group room: ${groupId}`);
                }
            });

            socket.emit('groupCreated', { groupId, groupName });
            groupCreationStatus.delete(socket.id);
        })
    }
});



// Handle block event
socket.on('block', (blockedUsername, callback) => {
    // Find the user who is blocking based on socketId
    db.get('SELECT id, username FROM users WHERE socketId = ?', [socket.id], (err, blocker) => {
        if (err || !blocker) {
            console.error('Blocker not found:', err);
            return callback({ success: false, error: 'Blocker not found' });
        }

        const blockerId = blocker.id;
        const blockerUsername = blocker.username;

        // Find the user being blocked by their username
        db.get('SELECT id, socketId FROM users WHERE username = ?', [blockedUsername], (err, blocked) => {
            if (err || !blocked) {
                console.error('Blocked user not found:', err);
                return callback({ success: false, error: 'Blocked user not found' });
            }

            const blockedId = blocked.id;
            const blockedSocketId = blocked.socketId;

            // Insert the block relationship into the blocked table
            db.run('INSERT INTO blocked (blocker, blocked) VALUES (?, ?)', [blockerId, blockedId], function(err) {
                if (err) {
                    console.error('Error inserting into blocked table:', err);
                    return callback({ success: false, error: 'Database error' });
                }

                // Remove any existing friendship between the users
                db.run('DELETE FROM friends WHERE (inviting = ? AND invited = ?) OR (inviting = ? AND invited = ?)', 
                    [blockerId, blockedId, blockedId, blockerId], (err) => {
                    if (err) {
                        console.error('Error removing friendship:', err);
                        return callback({ success: false, error: 'Database error' });
                    }

                    console.log(`Friendship between ${blockerUsername} and ${blockedUsername} removed due to block.`);

                    // Fetch updated friends lists and send them to both users
                    sendUpdatedFriendsList(blockerId);
                    sendUpdatedFriendsList(blockedId);

                    // Check if the blocked user has an active socket connection and notify them
                    if (blockedSocketId) {
                        io.to(blockedSocketId).emit('blockedNotification', blockerUsername);
                        console.log(`${blockedUsername} has been notified of the block.`);
                    } else {
                        console.log(`Blocked user ${blockedUsername} is not currently online.`);
                    }

                    // Notify the client (blocker) about the successful block
                    callback({ success: true, message: `You have blocked ${blockedUsername}` });

                    // Check if the blocker is in the groupInvite table and delete their entries
                    const deleteInviteSQL = `DELETE FROM groupInvite 
                                              WHERE inviting = ? OR invited = ?`;

                    db.run(deleteInviteSQL, [blockerId, blockerId], function(err) {
                        if (err) {
                            console.error('Error deleting group invites for blocker:', err);
                        } else {
                            console.log(`Removed group invites for blocker (${blockerUsername}).`);
                        }
                    });
                });
            });
        });
    });
});


// Helper function to fetch the updated friends list and send it to the user
const sendUpdatedFriendsList = (userId) => {
    const query = `
        SELECT 
            u.id AS id,
            u.username AS name,
            u.profileImage AS image,
            u.socketId AS socketId,
            CASE WHEN u.socketId IS NOT NULL THEN 1 ELSE 0 END AS online
        FROM friends f
        JOIN users u ON (f.inviting = u.id OR f.invited = u.id)
        WHERE (f.inviting = ? OR f.invited = ?) AND f.accepted = 1
        AND u.id != ?
    `;

    db.all(query, [userId, userId, userId], (err, friends) => {
        if (err) {
            console.error('Error fetching friends list:', err);
            return;
        }

        // Fetch the user's socket ID to send them the updated friends list
        db.get('SELECT socketId FROM users WHERE id = ?', [userId], (err, user) => {
            if (err || !user || !user.socketId) {
                console.error('User not found or not online:', err);
                return;
            }

            // Send the updated friends list to the client
            io.to(user.socketId).emit('friendsList', friends
            );
        });
    });
};



// Handling 'disconnect' event
socket.on('disconnect', () => {
    // First, find the user that disconnected based on the socketId
    db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, disconnectedUser) => {
        if (err || !disconnectedUser) {
            console.error('Disconnected user not found:', err);
            return;
        }

        const disconnectedUserId = disconnectedUser.id;

        // Clear the socketId and receiver fields
        db.run('UPDATE users SET socketId = NULL, receiver = NULL, groupRec = NULL WHERE id = ?', [disconnectedUserId], (err) => {
            if (err) {
                console.error('Error clearing socketId and receiver:', err);
            } else {
                console.log(`SocketId and receiver cleared for userId: ${disconnectedUserId}`);

                // Fetch groups of the disconnected user
                db.all(`
                    SELECT g.id AS groupId, g.name AS groupName, g.avatar AS groupAvatar
                    FROM groupInvite gi
                    JOIN groups g ON gi.groupId = g.id
                    WHERE gi.invited = ? AND gi.accepted = 1
                `, [disconnectedUserId], (err, groups) => {
                    if (err) {
                        console.error('Error fetching groups for disconnected user:', err);
                        return;
                    }

                    // Find all users in those groups
                    const groupIds = groups.map(group => group.groupId);
                    if (groupIds.length === 0) return; // No groups to process

                    const placeholders = groupIds.map(() => '?').join(',');
                    db.all(`
                        SELECT u.id AS userId, u.socketId, COUNT(u2.id) AS disconnectedCount
                        FROM users u
                        JOIN groupInvite gi ON gi.groupId IN (${placeholders})
                        LEFT JOIN users u2 ON u2.socketId IS NULL AND gi.invited = u2.id
                        WHERE gi.groupId IN (${placeholders}) AND u.socketId IS NOT NULL
                        GROUP BY u.id
                    `, [...groupIds, ...groupIds], (err, connectedUsers) => {
                        if (err) {
                            console.error('Error fetching connected users from groups:', err);
                            return;
                        }

                        // Check if there is exactly one disconnected user in those groups
                        const totalDisconnected = connectedUsers.reduce((count, user) => count + (user.disconnectedCount > 0 ? 1 : 0), 0);

                        if (totalDisconnected === 1) {
                            // Send groups to each connected user
                            connectedUsers.forEach(user => {
                                io.to(user.socketId).emit('disconnectedUserGroups', groups);
                            });
                        }
                    });
                });

                // Fetch the friends of the disconnected user
                fetchFriends(disconnectedUserId, (friends) => {
                    // Notify each friend about their updated friend list
                    friends.forEach(friend => {
                        if (friend.socketId) {
                            // Fetch the updated list of the friend's friends
                            fetchFriends(friend.id, (updatedFriendsList) => {
                                // Send the updated friend list to the friend
                                io.to(friend.socketId).emit('friendsList', updatedFriendsList);
                            });
                        }
                    });
                });
            }
        });
    });
});


// Helper function to fetch friends with username, profile image, and online status
const fetchFriends = (userId, callback) => {
    const query = `
        SELECT 
            u.id AS id,
            u.username AS name,
            u.profileImage AS image,
            u.socketId AS socketId,
            CASE WHEN u.socketId IS NOT NULL THEN 1 ELSE 0 END AS online
        FROM friends f
        JOIN users u ON (f.inviting = u.id OR f.invited = u.id)
        WHERE (f.inviting = ? OR f.invited = ?) AND u.id != ? AND f.accepted = 1
    `;

    db.all(query, [userId, userId, userId], (err, friends) => {
        if (err) {
            console.error('Error fetching friends:', err);
            callback([]);
        } else {
            callback(friends);
        }
    });
};



    
    function findBlocked(searchUser, socketId) {
        return new Promise((resolve, reject) => {
            // Find the sender by their socket ID
            db.get('SELECT id FROM users WHERE socketId = ?', [socketId], (err, sender) => {
                if (err || !sender) {
                    console.error('Sender not found:', err);
                    return reject(err);
                }
    
                // SQL query to find users excluding the sender and those they have blocked, and adding isFriend status
                const query = `
                    SELECT u.id, u.username, u.socketId, u.profileImage,  -- Include profileImage
                    CASE
                        WHEN EXISTS (
                            SELECT 1 FROM friends
                            WHERE (friends.inviting = u.id AND friends.invited = ?)  -- Sender is invited
                            OR (friends.invited = u.id AND friends.inviting = ?)     -- Sender is inviting
                        ) THEN 1
                        ELSE 0
                    END AS isFriend
                    FROM users u
                    WHERE u.username LIKE ? COLLATE NOCASE  -- 3rd placeholder
                    AND u.id != ?  -- Exclude the sender themselves
                    AND u.id NOT IN (
                        -- Exclude users who have blocked the sender
                        SELECT blocker FROM blocked WHERE blocked = ?  -- 4th placeholder
                    )
                    AND u.id NOT IN (
                        -- Exclude users blocked by the sender
                        SELECT blocked FROM blocked WHERE blocker = ?  -- 5th placeholder
                    );
                `;
    
                // Execute the query
                db.all(query, [`${sender.id}`, `${sender.id}`, `%${searchUser}%`, sender.id, sender.id, sender.id], (err, rows) => {
                    if (err) {
                        console.error(err);
                        return reject(err);
                    }
    
                    // Map through rows to add image file names
                    const modifiedRows = rows.map(row => {
                        const fileName = row.profileImage; // Extract filename or use default
                        return {
                            ...row, // Spread original row properties
                            profileImage: fileName // Replace profileImage with just the filename
                        };
                    });
    
                    resolve(modifiedRows);  // Resolve with the modified rows including filenames
                });
            });
        });
    }
    
    
    
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    //console.log(`Server is listening on port ${PORT}`);
});

