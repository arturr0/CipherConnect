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
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Use Buffer to create key from hex
const IV_LENGTH = 16; // For AES, this is always 16

// Function to encrypt a message
function encrypt(text) {
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex'); // Store IV with the encrypted message
}

// Function to decrypt a message
function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
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
        profileImage BLOB,
        FOREIGN KEY (receiver) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        senderId INTEGER,
        recId INTEGER,
        message TEXT,
        read INTEGER NOT NULL,
        sendTime TEXT NOT NULL,
        toDelete INTEGER DEFAULT 0, 
        FOREIGN KEY (senderId) REFERENCES users(id),
        FOREIGN KEY (recId) REFERENCES users(id)
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

// User registration
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
            if (err) return res.status(500).json({ message: 'User already exists' });
            res.status(200).json({ message: 'User registered successfully' });
        });
    });
});

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Invalid username or password' });

        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(401).json({ message: 'Invalid username or password' });

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, {
                httpOnly: true, 
                secure: true, 
                sameSite: 'None', // Explicitly set the SameSite attribute to 'None'
                maxAge: 3600000 // 1 hour in milliseconds
            });
            
            res.status(200).json({ message: 'Login successful' });
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
    
    

// Handle requests for previous messages
socket.on('sendMeMessages', (username, receiver) => {
    // Retrieve ID of the sender (username)
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, sender) => {
        if (err || !sender) {
            console.error('Error finding sender:', err);
            return;
        }

        // Retrieve ID and profileImage of the receiver (receiver username)
        db.get('SELECT id, profileImage FROM users WHERE username = ?', [receiver], (err, receiverResult) => {
            if (err || !receiverResult) {
                console.error('Error finding receiver:', err);
                return;
            }

            // Update the 'receiver' column in the 'users' table for the sender
            db.run('UPDATE users SET receiver = ? WHERE id = ?', [receiverResult.id, sender.id], (err) => {
                if (err) {
                    console.error('Error updating receiver for sender:', err);
                    return;
                }
                console.log(`Receiver updated successfully for user ${username}`);

                // Fetch messages between the sender and receiver, now including sendTime
                db.all(`
                    SELECT messages.id, 
                           messages.message, 
                           messages.read, 
                           messages.sendTime, 
                           messages.toDelete,   /* Fetch toDelete status */
                           sender.username AS senderUsername, 
                           receiver.username AS receiverUsername 
                    FROM messages 
                    JOIN users AS sender ON messages.senderId = sender.id 
                    JOIN users AS receiver ON messages.recId = receiver.id 
                    WHERE (messages.senderId = ? AND messages.recId = ?) 
                       OR (messages.senderId = ? AND messages.recId = ?)`,
                    [sender.id, receiverResult.id, receiverResult.id, sender.id],
                    (err, messages) => {
                        if (err) {
                            console.error('Error fetching messages:', err);
                            return;
                        }

                        // Decrypt each message and include sendTime
                        const decryptedMessages = messages.map(msg => {
                            try {
                                return {
                                    id: msg.id,  // Include the message ID for deletion later
                                    message: decrypt(msg.message),  // Decrypt the message text
                                    senderUsername: msg.senderUsername,
                                    receiverUsername: msg.receiverUsername,
                                    read: msg.read,
                                    time: msg.sendTime,
                                    toDelete: msg.toDelete
                                };
                            } catch (decryptionError) {
                                console.error('Error decrypting message:', decryptionError);
                                return null;  // Skip the message if it fails to decrypt
                            }
                        }).filter(msg => msg !== null);  // Filter out null (failed decryption)

                        // Log decrypted messages to verify they are correctly decrypted
                        console.log('Decrypted messages to send:', decryptedMessages);

                        // Send decrypted messages and the receiver's profile image separately
                        socket.emit('messagesResponse', {
                            messages: decryptedMessages,  // Array of decrypted messages
                            profileImage: receiverResult.profileImage  // The receiver's profile image
                        });

                        // Now mark messages as read if the receiver (user) has seen them
                        db.run(`
                            UPDATE messages 
                            SET read = 1 
                            WHERE recId = ? AND senderId = ? 
                              AND read = 0`,  // Only update unread messages
                            [sender.id, receiverResult.id],  // recId is the sender (user), senderId is the receiver
                            (err) => {
                                if (err) {
                                    console.error('Error marking messages as read:', err);
                                } else {
                                    console.log(`Messages marked as read between ${username} and ${receiver}`);
                                }
                            }
                        );

                        // Check for and delete messages that have 'toDelete' set to 1
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
        db.get('SELECT id, profileImage FROM users WHERE username = ?', [username], (err, user) => {
            if (err || !user) {
                console.error('User not found:', username);
                return;
            }
    
            // Update the user's socket ID
            db.run('UPDATE users SET socketId = ? WHERE id = ?', [socket.id, user.id], (err) => {
                if (err) {
                    console.error('Error updating socket ID:', err);
                    return;
                }
                
                // Emit the friends list to the logged-in user
                fetchFriends(user.id, (friends) => {
                    io.to(socket.id).emit('friendsList', friends); // Send list to logged-in user
    
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
    
                // Fetch the user again after socketId is updated
                db.get('SELECT id, profileImage FROM users WHERE socketId = ?', [socket.id], (err, updatedUser) => {
                    if (err || !updatedUser) {
                        console.error('Updated user not found:', err);
                        return;
                    }
    
                    // Emit user info (including profile image if it exists)
                    io.to(socket.id).emit('user info', {
                        id: updatedUser.id,
                        profileImage: updatedUser.profileImage || null
                    });
    
                    // Fetch pending invitations
                    db.all(`
                        SELECT u.username, f.inviting 
                        FROM friends f
                        JOIN users u ON f.inviting = u.id
                        WHERE f.invited = ? AND f.accepted = 0`, [updatedUser.id], (err, rows) => {
                        if (err) {
                            console.error('Error fetching invitations:', err);
                            return;
                        }
    
                        // Process and send pending invitations
                        const pendingInvitations = rows.map(row => ({
                            username: row.username,
                            invitingId: row.inviting
                        }));
    
                        io.to(socket.id).emit('pendingInvitations', pendingInvitations);
                    });
    
                    // Count unread messages
                    db.all(`
                        SELECT senderId, COUNT(*) AS unreadCount 
                        FROM messages 
                        WHERE recId = ? AND read = 0 
                        GROUP BY senderId`, [updatedUser.id], (err, unreadCounts) => {
                        if (err) {
                            console.error('Error fetching unread messages count:', err);
                            return;
                        }
    
                        // Fetch usernames for unread counts
                        const unreadWithUsernames = unreadCounts.map(count => {
                            return new Promise((resolve) => {
                                db.get('SELECT username FROM users WHERE id = ?', [count.senderId], (err, sender) => {
                                    if (err || !sender) {
                                        console.error('Error fetching sender username:', err);
                                        resolve({ username: null, unreadCount: count.unreadCount });
                                    } else {
                                        resolve({ username: sender.username, unreadCount: count.unreadCount });
                                    }
                                });
                            });
                        });
    
                        // Resolve all promises to get usernames
                        Promise.all(unreadWithUsernames).then(results => {
                            // Emit the unread message counts back to the client
                            io.to(socket.id).emit('unread message counts', results);
                        });
                    });
                    // Fetch pending group invitations
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

                        // Map the results to a more convenient format
                        const pendingGroupInvites = groupInvites.map(invite => ({
                            invitingUsername: invite.invitingUsername,
                            groupId: invite.groupId,
                            groupName: invite.groupName
                        }));

                        // Emit the pending group invitations to the logged-in user
                        io.to(socket.id).emit('groupInvites', pendingGroupInvites);
                    });
                    db.all(`
                        SELECT u.username AS invitingUsername, gi.groupId, gi.groupName 
                        FROM groupInvite gi
                        JOIN users u ON gi.inviting = u.id
                        WHERE (gi.invited = ? OR gi.inviting = ?) AND gi.accepted = 1
                    `, [updatedUser.id, updatedUser.id], (err, groupInvites) => {
                        if (err) {
                            console.error('Error fetching group invitations:', err);
                            return;
                        }
                    
                        // Map the results to a more convenient format
                        // Assuming groupInvites is an array of objects with groupId properties
                        const myGroups = groupInvites.map(invite => invite.groupId); // Create an array of groupIds

                        // Join each groupId as a room
                        myGroups.forEach(groupId => {
                            socket.join(`${groupId}`); // Join the room using groupId
                            console.log(`User joined room: ${groupId}`); // Log the joined room
                        });

                        // Emit the pending group invitations to the logged-in user
                        //io.to(socket.id).emit('groupInvites', pendingGroupInvites);
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
    
    
    
    
    // socket.on('chatMessage', ({ message }) => {
    //     db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, user) => {
    //         if (err || !user) {
    //             console.error('User not found for socket:', socket.id);
    //             return;
    //         }

    //         const encryptedMessage = encrypt(message);
    //         db.run('INSERT INTO messages (senderId, message) VALUES (?, ?)', [user.id, encryptedMessage], (err) => {
    //             if (err) {
    //                 console.error('Error saving message:', err);
    //                 return;
    //             }

    //             db.get('SELECT message FROM messages WHERE senderId = ? ORDER BY id DESC LIMIT 1', [user.id], (err, row) => {
    //                 if (err) {
    //                     console.error('Error retrieving message:', err);
    //                     return;
    //                 }

    //                 const decryptedMessage = decrypt(row.message);
    //                 io.to(socket.id).emit('message', { user: user.username, message: decryptedMessage });
    //             });
    //         });
    //     });
    // });
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
    
    
    // socket.on('confirm invite', ({ decision, invitingName }) => {
    //     // Find the invited user's info (current user)
    //     db.get('SELECT username, profileImage FROM users WHERE socketId = ?', [socket.id], (err, invited) => {
    //         if (err || !invited) {
    //             console.error('Invited user not found:', err);
    //             return;
    //         }
    
    //         const invitedName = invited.username;
    //         const invitedImage = invited.profileImage;
    
    //         // Find the inviting user's socketId and profileImage based on their username (invitingName)
    //         db.get('SELECT socketId, profileImage FROM users WHERE username = ?', [invitingName], (err, inviting) => {
    //             if (err || !inviting) {
    //                 console.error('Inviting user not found:', err);
    //                 return;
    //             }
    
    //             const invitingSocketId = inviting.socketId;
    //             const invitingImage = inviting.profileImage; // Fetching inviting user's profile image
    
    //             // Only proceed if the decision is to accept the invitation
    //             if (decision) {
    //                 // Update the `accepted` column to 1 in the friends table
    //                 db.run('UPDATE friends SET accepted = 1 WHERE inviting = ? AND invited = ?', [inviting.id, invited.id], (err) => {
    //                     if (err) {
    //                         console.error('Error updating friends table:', err);
    //                     } else {
    //                         console.log(`Invitation accepted by user ${invited.id}`);
    
    //                         // Send the invited user's details to the inviting user's socket
    //                         io.to(invitingSocketId).emit('invitationConfirmed', {
    //                             invitedName: invitedName,
    //                             invitedImage: invitedImage
    //                              // Sending the inviting user's profile image
    //                         });
    
    //                         // Optionally, send the inviting user's details to the invited user's socket
    //                         socket.emit('invitationConfirmed', {
    //                             invitingName: invitingName,
    //                             invitingImage: invitingImage, // If you want to send the inviting user's profile image back
    //                         });
    //                     }
    //                 });
    //             } else {
    //                 // If rejected, delete the entry from the friends table
    //                 db.run('DELETE FROM friends WHERE inviting = ? AND invited = ?', [inviting.id, invited.id], (err) => {
    //                     if (err) {
    //                         console.error('Error deleting from friends table:', err);
    //                     } else {
    //                         console.log(`Invitation rejected by user ${invited.id}`);
    //                     }
    //                 });
    //             }
    //         });
    //     });
    // });
    // socket.on('confirm invite', ({ decision, invitingName }) => {
    //     // Find the invited user's info (current user)
    //     db.get('SELECT id, username, profileImage FROM users WHERE socketId = ?', [socket.id], (err, invited) => {
    //         if (err || !invited) {
    //             console.error('Invited user not found:', err);
    //             return;
    //         }
    
    //         const invitedId = invited.id; // Ensure you get the ID here
    //         const invitedName = invited.username;
    //         const invitedImage = invited.profileImage;
    
    //         console.log('Invited User ID:', invitedId); // Log the invited user ID
    
    //         // Find the inviting user's socketId and profileImage based on their username (invitingName)
    //         db.get('SELECT id, socketId, profileImage FROM users WHERE username = ?', [invitingName], (err, inviting) => {
    //             if (err || !inviting) {
    //                 console.error('Inviting user not found:', err);
    //                 return;
    //             }
    
    //             const invitingId = inviting.id;
    //             const invitingSocketId = inviting.socketId;
    //             const invitingImage = inviting.profileImage; // Fetching inviting user's profile image
    
    //             // Log the IDs
    //             console.log('Inviting ID:', invitingId);
    //             console.log('Invited ID:', invitedId);
    
    //             // Only proceed if the decision is to accept the invitation
    //             if (decision) {
    //                 // Update the `accepted` column to 1 in the friends table
    //                 db.run('UPDATE friends SET accepted = 1 WHERE inviting = ? AND invited = ?', [invitingId, invitedId], function(err) {
    //                     if (err) {
    //                         console.error('Error updating friends table:', err);
    //                     } else if (this.changes === 0) {
    //                         console.log('No rows updated. Check if inviting and invited IDs are correct.');
    //                     } else {
    //                         console.log(`Invitation accepted by user ${invitedId}`); // Use invitedId here
    
    //                         // Send the invited user's details to the inviting user's socket
    //                         io.to(invitingSocketId).emit('invitationConfirmed', {
    //                             invitedName: invitedName,
    //                             invitedImage: invitedImage
    //                         });
    
    //                         // Optionally, send the inviting user's details to the invited user's socket
    //                         socket.emit('invitationConfirmed', {
    //                             invitingName: invitingName,
    //                             invitingImage: invitingImage // If you want to send the inviting user's profile image back
    //                         });
    //                     }
    //                 });
    //             } else {
    //                 // If rejected, delete the entry from the friends table
    //                 db.run('DELETE FROM friends WHERE inviting = ? AND invited = ?', [invitingId, invitedId], (err) => {
    //                     if (err) {
    //                         console.error('Error deleting from friends table:', err);
    //                     } else {
    //                         console.log(`Invitation rejected by user ${invitedId}`);
    //                     }
    //                 });
    //             }
    //         });
    //     });
    // });
    //tbale but with own data
    // socket.on('confirm invite', ({ decision, invitingName }) => {
    //     // Find the invited user's info (current user)
    //     db.get('SELECT id, username, profileImage FROM users WHERE socketId = ?', [socket.id], (err, invited) => {
    //         if (err || !invited) {
    //             console.error('Invited user not found:', err);
    //             return;
    //         }
    
    //         const invitedId = invited.id;
    //         const invitedName = invited.username;
    //         const invitedImage = invited.profileImage;
    
    //         // Find the inviting user's socketId and profileImage based on their username (invitingName)
    //         db.get('SELECT id, socketId, profileImage FROM users WHERE username = ?', [invitingName], (err, inviting) => {
    //             if (err || !inviting) {
    //                 console.error('Inviting user not found:', err);
    //                 return;
    //             }
    
    //             const invitingId = inviting.id;
    //             const invitingSocketId = inviting.socketId;
    //             const invitingImage = inviting.profileImage;
    
    //             // Only proceed if the decision is to accept the invitation
    //             if (decision) {
    //                 // Update the `accepted` column to 1 in the friends table
    //                 db.run('UPDATE friends SET accepted = 1 WHERE inviting = ? AND invited = ?', [invitingId, invitedId], function (err) {
    //                     if (err) {
    //                         console.error('Error updating friends table:', err);
    //                     } else if (this.changes === 0) {
    //                         console.log('No rows updated. Check if inviting and invited IDs are correct.');
    //                     } else {
    //                         console.log(`Invitation accepted by user ${invitedId}`);
    
    //                         // Fetch the updated friends list for both users (where accepted = 1)
    //                         const fetchFriends = (userId, callback) => {
    //                             const query = `
    //                                 SELECT u.username, u.profileImage
    //                                 FROM friends f
    //                                 JOIN users u ON (f.inviting = u.id OR f.invited = u.id)
    //                                 WHERE (f.inviting = ? OR f.invited = ?) AND f.accepted = 1
    //                             `;
    //                             db.all(query, [userId, userId], (err, friends) => {
    //                                 if (err) {
    //                                     console.error('Error fetching friends:', err);
    //                                 }
    //                                 callback(friends);
    //                             });
    //                         };
    
    //                         // Fetch and send the invited user's friends list
    //                         fetchFriends(invitedId, (invitedFriends) => {
    //                             socket.emit('friendsList', {
    //                                 friends: invitedFriends,
    //                             });
    //                         });
    
    //                         // Fetch and send the inviting user's friends list
    //                         fetchFriends(invitingId, (invitingFriends) => {
    //                             io.to(invitingSocketId).emit('friendsList', {
    //                                 friends: invitingFriends,
    //                             });
    //                         });
    
    //                         // Optionally, send the invited user's details to the inviting user's socket
    //                         io.to(invitingSocketId).emit('invitationConfirmed', {
    //                             invitedName: invitedName,
    //                             invitedImage: invitedImage
    //                         });
    
    //                         // Optionally, send the inviting user's details to the invited user's socket
    //                         socket.emit('invitationConfirmed', {
    //                             invitingName: invitingName,
    //                             invitingImage: invitingImage
    //                         });
    //                     }
    //                 });
    //             } else {
    //                 // If rejected, delete the entry from the friends table
    //                 db.run('DELETE FROM friends WHERE inviting = ? AND invited = ?', [invitingId, invitedId], (err) => {
    //                     if (err) {
    //                         console.error('Error deleting from friends table:', err);
    //                     } else {
    //                         console.log(`Invitation rejected by user ${invitedId}`);
    //                     }
    //                 });
    //             }
    //         });
    //     });
    // });
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
    
                        // Send group details: name, avatar, and group id
                        db.get(`SELECT name, avatar FROM groups WHERE id = ?`, [invitingName], (err, group) => {
                            if (err) {
                                console.error('Error retrieving group details:', err);
                                return;
                            }
    
                            socket.emit('group confirmed', {
                                groupId: invitingName,
                                groupName: group.name,
                                groupAvatar: group.avatar
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
    
    // Set the flag to true for this socket ID, indicating that group creation is in progress
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

                const blockedUsers = new Set();
                blockRows.forEach(blockRow => {
                    blockedUsers.add(blockRow.blocker);
                });

                console.log("Blocked users: ", blockedUsers);

                const validInvitedUsers = invited.filter(user => {
                    const invitedUserId = userIds[user];
                    return invitedUserId && !blockedUsers.has(invitedUserId);
                });

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
                            
                            // Make the invited user join the group room
                            //io.sockets.sockets.get(invitedSocketId)?.join(`${groupId}`);
                            //console.log(`User ${invitedUser} joined group room: ${groupId}`);
                        }
                    }
                });
            });
    
            // Invite the creator and make them join the group room
            db.run(insertInviteSQL, [userIds[username], userIds[username], groupId, groupName, 1], err => {
                if (err) {
                    console.error("Error inserting creator's invite:", err);
                } else {
                    // Make the creator join the group room
                    socket.join(`${groupId}`);
                    console.log(`Creator ${username} joined group room: ${groupId}`);
                }
            });
    
            socket.emit('groupCreated', { groupId, groupName });
    
            // Reset the flag after group creation is done
            groupCreationStatus.delete(socket.id);
        });
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
        db.run('UPDATE users SET socketId = NULL, receiver = NULL WHERE id = ?', [disconnectedUserId], (err) => {
            if (err) {
                console.error('Error clearing socketId and receiver:', err);
            } else {
                console.log(`SocketId and receiver cleared for userId: ${disconnectedUserId}`);

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

