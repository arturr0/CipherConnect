const socket = io.connect('http://localhost:3004');
const baseUrl = window.location.origin;
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const findUsers = document.getElementById('findUsers');
    const receiverAvatar = document.getElementById('receiverAvatar');
    const chat = document.getElementById('message-container');
    const invCounter = document.getElementById('invCounter');
    const messCounter = document.getElementById('messCounter');
    const groupCounter = document.getElementById('groupCounter');
    const unreadMessages = document.createElement('div');
    const receiverElement = document.getElementById('receiverName');
    const friendsContainer = document.getElementById('friendsContainer');
    let messageValue = 0;
    let receiver = '';
    const cryptoDiv = document.getElementById("crypto");
    const originalWidth = cryptoDiv.offsetWidth;
    document.getElementById("crypto").addEventListener('click', () => {
        cryptoDiv.style.width = `${originalWidth}px`
        if(document.getElementById("crypto").textContent.includes("No Storing Messages")) {
            
            
            document.getElementById("crypto").textContent = 'Store Messages';
        }
        else document.getElementById("crypto").textContent = 'No Storing Messages';
        const icon = document.createElement('i')
        icon.classList.add('icon-user-secret');
        icon.classList.add('accIon');
        document.getElementById("crypto").appendChild(icon); // Change only the text in the crypto div
    });
    
    const username = localStorage.getItem('username');
    if (document.getElementById("message")) {
        document.getElementById("message").addEventListener("keydown", function(e) {
            let messageSent = document.getElementById("message").value;
            const inputValString = String(messageSent);
            
            if (e.key === 'Enter') {
                console.log(receiver)
                e.preventDefault();
                if (messageSent !== null && messageSent.trim() !== '' && receiver !== '') {
                    //const chat = document.getElementById("chat");
                    //const receiver = 'art2';
                    console.log("my mess");
                    chat.innerHTML += (`<div class="bubble left" style="word-break: break-word">${inputValString}</div>`);
                    adjustMarginForScrollbar();
                    
                    console.log(username);
                    socket.emit('chatMessage', { username, messageSent, receiver });
                    document.getElementById("message").value = "";
                    document.getElementById("message").style.height = '80px';
                    console.log(messageSent);
                    jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
                }
            }
        });
    }
    const searchUsers = document.getElementById('searchUsers');
    const friends = document.getElementById('friends');

    function updatesearchUsersWidth() {
        // Calculate the width of the #friends div
        const friendsWidth = friends.offsetWidth; // Get width in pixels
        // Set the width of the #searchUsers div to match the #friends width
        searchUsers.style.width = `${friendsWidth}px`; // Set width in pixels
    }

// Call the function initially to set the width when the page loads
    updatesearchUsersWidth();

    findUsers.addEventListener('click', () => {
        if (searchUsers.classList.contains('move-left')) {
            // Move both elements to the right
            searchUsers.classList.remove('move-left');
            searchUsers.classList.add('move-right');
            
            friends.classList.remove('move-left');
            friends.classList.add('move-right');
        } else {
            // Move both elements to the left
            searchUsers.classList.remove('move-right');
            searchUsers.classList.add('move-left');
            
            friends.classList.remove('move-right');
            friends.classList.add('move-left');
        }
    });

// Add resize event listener
    window.addEventListener('resize', updatesearchUsersWidth);

    
    socket.on('connect', () => {
        const username = localStorage.getItem('username');
        socket.emit('login', username);
        console.log('Username emitted to server:', username);
    });
    socket.on('invitationConfirmed', (data) => {
        console.log(data);
        
            
            
            
            
            
        
    });
    
    socket.on('friendsList', (data) => {
        console.log(data);
        // Clear previous user list
        friendsContainer.innerHTML = ''; // Clear the previous list
        
        // Show loading icon when starting to append users
        // loadingIcon.classList.remove('display');
        // loadingIcon.classList.add('animate-spin');
        //document.getElementById("users").appendChild(loadingIcon);
    
        const fragment = document.createDocumentFragment();
    
        // Loop over the found users
        data.forEach((friend) => {
            const userDiv = document.createElement('div');
            userDiv.classList.add('user');
    
            const profileContainer = document.createElement('div');
            profileContainer.classList.add('profile-container');
    
            // Create initials element but keep it hidden initially
            const initials = document.createElement('div');
            initials.classList.add('initials');
            initials.textContent = friend.name.charAt(0).toUpperCase();
            initials.style.visibility = 'hidden';  // Keep hidden initially
            profileContainer.appendChild(initials);
    
            userDiv.appendChild(profileContainer);
    
            const userInfoDiv = document.createElement('div');
            userInfoDiv.classList.add('user-info');
            const usernameText = document.createElement('div');
            usernameText.classList.add('username');
            usernameText.textContent = friend.name;
            userInfoDiv.appendChild(usernameText);
    
            
            const buttonsDiv = document.createElement('div');
            buttonsDiv.classList.add('buttons');
            // Create send message button
            const sendButton = document.createElement('button');
            sendButton.classList.add('send');
            sendButton.value = friend.name;
            const sendIcon = document.createElement('i');
            sendIcon.classList.add('icon-comment');
            sendButton.appendChild(sendIcon);
            buttonsDiv.appendChild(sendButton);
    
            // Create block button
            const blockButton = document.createElement('button');
            blockButton.classList.add('block');
            blockButton.value = friend.name;
            const blockIcon = document.createElement('i');
            blockIcon.classList.add('icon-block-1');
            blockButton.appendChild(blockIcon);
            buttonsDiv.appendChild(blockButton);
    
            // Append buttons to userInfoDiv
            userInfoDiv.appendChild(buttonsDiv);
    
            // Append userInfoDiv to userDiv
            userDiv.appendChild(userInfoDiv);
            userDiv.appendChild(userInfoDiv);
            fragment.appendChild(userDiv);
            //userDiv.appendChild(sendButton);  // Append send button
        
            sendButton.addEventListener('click', async () => {
                receiver = sendButton.value;
    
                // Emit findUsers without awaiting the response
                //socket.emit('findUsers', searchUser); // This might be adjusted based on your logic
    
                // Assume that the server will respond with found users
                
                    
                    
                        receiverElement.textContent = receiver;
    
                        // Clear existing content in #receiverAvatar
                        receiverAvatar.innerHTML = ''; 
                        const profileContainer = userDiv.querySelector('.profile-container');
    
                        // Check for the presence of an img element
                        const img = profileContainer.querySelector('img.profile-image');
                        const initialsElement = profileContainer.querySelector('.initials');
    
                        // Append the image or initials based on availability
                        if (img) {
                            const clonedImg = img.cloneNode();
                            clonedImg.classList.remove('profile-image');
                            clonedImg.id = 'receiverAvatar';
                            receiverAvatar.appendChild(clonedImg);
                        } else if (initialsElement) {
                            const clonedInitials = initialsElement.cloneNode(true);
                            clonedInitials.classList.remove('initials');
                            clonedInitials.id = 'receiverInitials';
                            receiverAvatar.appendChild(clonedInitials);
                        }
    
                        socket.emit('sendMeMessages', username, receiver);
                    
                
            });
            
            
                // Select all elements with the class 'send'
    const sendButtons = document.querySelectorAll('.send');
    
                
                blockButton.addEventListener('click', () => {
                    blockButton.disabled = true;
                    console.log("click");
                    const blockedUser = blockButton.value;
                    socket.emit('block', blockedUser, (response) => {
                        if (response.success) {
                            socket.emit('findUsers', searchUser);
                            console.log(response.message);
                        } else {
                            console.error('Failed to block user:', response.error);
                        }
                    });
                });
                
            // Now load the image asynchronously
            // if (friend.image) {
            //     console.log('img out');
            //     loadImageAsync(friend.image)
            //         .then((userImage) => {
            //             console.log(userImage);
            //             userImage.alt = `${user.username}'s profile image`;
            //             userImage.classList.add('profile-image');
            //             initials.style.display = 'none';  // Keep initials hidden if the image loads
            //             profileContainer.appendChild(userImage);
            //             console.log(profileContainer);
            //         })
            //         .catch((error) => {
            //             //console.log(`Failed to load image for user: ${user.username}`, error.message);
            //             initials.style.visibility = 'visible';  // Show initials if image fails to load
            //         });
            // } else {
            //     initials.style.visibility = 'visible';  // Show initials if there's no image
            // }
            if (friend.image) {
    loadImageAsync(friend.image)
        .then((userImage) => {
            console.log('Image loaded:', userImage);

            userImage.alt = `${friend.name}'s profile image`;
            userImage.classList.add('profile-image');
            
            initials.style.display = 'none';  // Hide initials when the image loads

            // Check if the image is already appended
            if (!profileContainer.querySelector('img.profile-image')) {
                console.log('Appending image to profileContainer');
                profileContainer.appendChild(userImage);
            } else {
                console.log('Image already exists in profileContainer');
            }
            
        })
        .catch((error) => {
            console.error(`Failed to load image for user: ${friend.name}`, error.message);
            initials.style.visibility = 'visible';  // Show initials if image fails to load
        });
} else {
    initials.style.visibility = 'visible';  // Show initials if there's no image
}

        });
    
        friendsContainer.appendChild(fragment);
    });
    socket.on('unread message counts', (unreadCounts) => {
        let newMessageCntr = 0;
        unreadCounts.forEach(newMessage => {
            const unreadMessage = document.createElement('div');
            unreadMessage.classList.add('unreadMessages');
            unreadMessage.setAttribute('value', `${newMessage.unreadCount}`);
            unreadMessage.setAttribute('data-username', newMessage.username); // Set data-username for this user
            unreadMessage.textContent = `${newMessage.username} ${newMessage.unreadCount}`;
            document.getElementById("messagesContent").appendChild(unreadMessage);
            newMessageCntr += newMessage.unreadCount// Set initial value to 1    
        });
        messCounter.setAttribute('value', newMessageCntr);
        messCounter.textContent = newMessageCntr;
    //     let existingMessage = document.querySelector(`.unreadMessages[data-username="${user}"]`);

    // // Check if the user's unread message div already exists
    // if (!existingMessage) {
    //     // Create a new unread message div for the specific user
    //     const unreadMessage = document.createElement('div');
    //     unreadMessage.classList.add('unreadMessages');
    //     unreadMessage.setAttribute('value', '1'); // Set initial value to 1
    //     unreadMessage.setAttribute('data-username', user); // Set data-username for this user
    //     unreadMessage.textContent = `${user} 1`; // Display initial unread count

    //     // Append to the messages content
    //     document.getElementById("messagesContent").appendChild(unreadMessage);
    // } else {
    //     // If the element exists, update its value
    //     let currentValue = parseInt(existingMessage.getAttribute('value'), 10) || 0; // Default to 0 if NaN
    //     currentValue++; // Increment the value

    //     // Set the new value and update displayed text
    //     existingMessage.setAttribute('value', currentValue);
    //     existingMessage.textContent = `${user} ${currentValue}`;
    // }

    // // Update the overall message counter
    // let messageValue = parseInt(messCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
    // messageValue++;
    // console.log(messageValue);
    // messCounter.setAttribute('value', messageValue);
    // messCounter.textContent = messageValue;
    });
    socket.on('blockedNotification', (data) => {
        console.log(data);
        socket.emit('findUsers', searchUser);
    });
    socket.on('user info', ({ id, profileImage }) => {
        console.log(`User ID: ${id}`);
        if (profileImage != null) document.getElementById("initials").remove();
        else {
            document.getElementById("initials").classList.remove('display');
            document.getElementById("initials").style.visibility = 'visible';
        }
        // Check if profile image exists
        if (profileImage) {
            const avatarContainer = document.getElementById("avatarOrInitials");
            const existingAvatar = document.getElementById('avatar');
    
            // Remove existing avatar if any
            // if (existingAvatar) {
            //     existingAvatar.remove();
            // }
    
            const avatar = document.createElement('div');
            avatar.id = 'avatar';
            avatarContainer.appendChild(avatar);
    
            const img = new Image();
            img.src = profileImage; // Use the emitted profile image path
            img.style.width = '100%';
            img.style.height = '100%';
            img.style.borderRadius = '50%';
            img.style.objectFit = 'cover';
    
            avatar.appendChild(img);
        } else {
            // Handle the case where there's no profile image
            console.log('No profile image found.');
            // Optionally show a placeholder or initials
        }
    });
    
    socket.on('avatar', (relativePath) => {
        const divToRemove = document.getElementById('initials');
        const divToRemove1 = document.getElementById('avatar');
        if (divToRemove) divToRemove.remove();
        if (divToRemove1) divToRemove1.remove();    
             // Removes the div from the DOM
            const avatar = document.createElement('div');
            avatar.id = 'avatar';
            document.getElementById("avatarOrInitials").appendChild(avatar);
    
            const img = new Image();
            img.src = relativePath;
            
            // Set styles for the image
            img.style.width = '100%'; // Make the image fill the div
            img.style.height = '100%'; // Make the image fill the div
            img.style.borderRadius = '50%'; // Apply border radius to the image
            img.style.objectFit = 'cover'; // Optional: cover the div while maintaining aspect ratio
    
            avatar.appendChild(img);
        
    });
    
    
    const messages = document.getElementById('messages');
    const formMessage = document.getElementById('chat-form');
    const inputMessage = document.getElementById('message');


// Update the receiver variable when the input changes
// receivers.addEventListener('input', () => {
//     receiver = receivers.value.trim(); // Update on input change
//     console.log('Updated receiver:', receiver);
// });

// formMessage.addEventListener('submit', (e) => {
//     e.preventDefault();
//     const message = inputMessage.value.trim();
//     const user = localStorage.getItem('username');
    
//     // Log the receiver and message
//     if (!message || !receiver) {
//         console.log('Message or receiver is missing');
//         return;  // Exit if either the message or receiver is empty
//     }
    
//     console.log('Submitting message:', receiver, message); // Log the receiver and message if valid
    
//     socket.emit('chatMessage', { user, message, receiver });
//     inputMessage.value = ''; // Clear the message input after sending
// });



    const usersDiv = document.getElementById('users');
    let searchUser = '';

    searchInput.addEventListener('input', () => {
        searchUser = searchInput.value.trim();
        if (searchUser) {
            console.log('Input search user:', searchUser);
            socket.emit('findUsers', searchUser);
        } else {
            usersDiv.innerHTML = '';
        }
    });

// Utility function to load an image using a Promise
// Utility function to load an image with a timeout for better control
function loadImageAsync(src, timeout = 500) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        let timedOut = false;
        console.log('img')
        // Reject after timeout to prevent infinite waiting for slow-loading images
        const timer = setTimeout(() => {
            timedOut = true;
            reject(new Error(`Image load timed out for ${src}`));
        }, timeout);

        img.src = src;

        img.onload = () => {
            if (!timedOut) {
                clearTimeout(timer); // Clear the timeout if it loads in time
                resolve(img);
            }
        };

        img.onerror = () => {
            if (!timedOut) {
                clearTimeout(timer);
                reject(new Error(`Image failed to load for ${src}`));
            }
        };
    });
}

// Listen for 'foundUsers' event
// Assuming this is your loading icon
const loadingIcon = document.querySelector('.icon-spin3'); // Ensure this selects your loading icon

// Listen for 'foundUsers' event
socket.on('inviteProcessed', () => {
    socket.emit('findUsers', searchUser);
    console.log('Find users after invite:', searchUser);
});
socket.on('foundUsers', async (founded) => {
    console.log('Found users:', founded);
    
    // Clear previous user list
    usersDiv.innerHTML = ''; // Clear the previous list

    // Show loading icon when starting to append users
    // loadingIcon.classList.remove('display');
    // loadingIcon.classList.add('animate-spin');
    //document.getElementById("users").appendChild(loadingIcon);

    const fragment = document.createDocumentFragment();

    // Loop over the found users
    founded.forEach((user) => {
        const userDiv = document.createElement('div');
        userDiv.classList.add('user');

        const profileContainer = document.createElement('div');
        profileContainer.classList.add('profile-container');

        // Create initials element but keep it hidden initially
        const initials = document.createElement('div');
        initials.classList.add('initials');
        initials.textContent = user.username.charAt(0).toUpperCase();
        initials.style.visibility = 'hidden';  // Keep hidden initially
        profileContainer.appendChild(initials);

        userDiv.appendChild(profileContainer);

        const userInfoDiv = document.createElement('div');
        userInfoDiv.classList.add('user-info');
        const usernameText = document.createElement('div');
        usernameText.classList.add('username');
        usernameText.textContent = user.username;
        userInfoDiv.appendChild(usernameText);

        const buttonsDiv = document.createElement('div');
        buttonsDiv.classList.add('buttons');
        // Create buttons and append to buttonsDiv...
        const inviteButton = document.createElement('button');
        inviteButton.classList.add('invite');
        inviteButton.value = user.username;
        const inviteIcon = document.createElement('i');
        inviteIcon.classList.add('icon-user-plus');
        inviteButton.appendChild(inviteIcon);
        if (user.isFriend != 1) buttonsDiv.appendChild(inviteButton);

        // Create send message button
        const sendButton = document.createElement('button');
        sendButton.classList.add('send');
        sendButton.value = user.username;
        const sendIcon = document.createElement('i');
        sendIcon.classList.add('icon-comment');
        sendButton.appendChild(sendIcon);
        buttonsDiv.appendChild(sendButton);

        // Create block button
        const blockButton = document.createElement('button');
        blockButton.classList.add('block');
        blockButton.value = user.username;
        const blockIcon = document.createElement('i');
        blockIcon.classList.add('icon-block-1');
        blockButton.appendChild(blockIcon);
        buttonsDiv.appendChild(blockButton);

        // Append buttons to userInfoDiv
        userInfoDiv.appendChild(buttonsDiv);

        // Append userInfoDiv to userDiv
        userDiv.appendChild(userInfoDiv);
        userDiv.appendChild(userInfoDiv);
        fragment.appendChild(userDiv);
        //userDiv.appendChild(sendButton);  // Append send button
    
        sendButton.addEventListener('click', async () => {
            receiver = sendButton.value;

            // Emit findUsers without awaiting the response
            socket.emit('findUsers', searchUser); // This might be adjusted based on your logic

            // Assume that the server will respond with found users
            socket.once('foundUsers', (foundUsers) => {
                const foundUser = foundUsers.find(u => u.username === receiver);
                if (foundUser) {
                    receiverElement.textContent = receiver;

                    // Clear existing content in #receiverAvatar
                    receiverAvatar.innerHTML = ''; 
                    const profileContainer = userDiv.querySelector('.profile-container');

                    // Check for the presence of an img element
                    const img = profileContainer.querySelector('img.profile-image');
                    const initialsElement = profileContainer.querySelector('.initials');

                    // Append the image or initials based on availability
                    if (img) {
                        const clonedImg = img.cloneNode();
                        clonedImg.classList.remove('profile-image');
                        clonedImg.id = 'receiverAvatar';
                        receiverAvatar.appendChild(clonedImg);
                    } else if (initialsElement) {
                        const clonedInitials = initialsElement.cloneNode(true);
                        clonedInitials.classList.remove('initials');
                        clonedInitials.id = 'receiverInitials';
                        receiverAvatar.appendChild(clonedInitials);
                    }

                    socket.emit('sendMeMessages', username, receiver);
                }
            });
        });
        
        
            // Select all elements with the class 'send'
const sendButtons = document.querySelectorAll('.send');


            blockButton.addEventListener('click', () => {
                blockButton.disabled = true; 
                const blockedUser = blockButton.value;
                socket.emit('block', blockedUser, (response) => {
                    if (response.success) {
                        socket.emit('findUsers', searchUser);
                        console.log(response.message);
                    } else {
                        console.error('Failed to block user:', response.error);
                    }
                });
            });
            inviteButton.addEventListener('click', () => {
                const invitedUser = inviteButton.value;
                console.log('Inviting user:', invitedUser); 
                inviteButton.disabled = true; // Disable button to prevent multiple invites
                socket.emit('invite', invitedUser);
    
                // Reset the user list and then re-fetch after processing the invite
                
            });
        // Now load the image asynchronously
        if (user.profileImage) {
            loadImageAsync(user.profileImage)
                .then((userImage) => {
                    userImage.alt = `${user.username}'s profile image`;
                    userImage.classList.add('profile-image');
                    initials.style.display = 'none';  // Keep initials hidden if the image loads
                    profileContainer.appendChild(userImage);
                })
                .catch((error) => {
                    console.log(`Failed to load image for user: ${user.username}`, error.message);
                    initials.style.visibility = 'visible';  // Show initials if image fails to load
                });
        } else {
            initials.style.visibility = 'visible';  // Show initials if there's no image
        }
    });

    usersDiv.appendChild(fragment);
    
    // Hide loading icon after appending users
    // loadingIcon.classList.add('display');
    // loadingIcon.classList.remove('animate-spin');
    // document.getElementById("users").removeChild(loadingIcon);
});















// Helper function to create a fallback avatar with the first character of the username
function appendFallbackAvatar(userDiv, username) {
    const fallbackDiv = document.createElement('div');
    fallbackDiv.classList.add('profile-fallback');
    fallbackDiv.textContent = username.charAt(0).toUpperCase(); // Use the first character of the username

    // Append the fallback div instead of the image
    userDiv.appendChild(fallbackDiv);
}





socket.on('message', (data) => {
    console.log(data);

    // Handle message from the receiver
    if (data.user === receiver) {
        handleIncomingMessage(data.message);
    } else {
        handleOtherMessage(data.user);
    }
});

function handleIncomingMessage(message) {
    adjustMarginForScrollbar();
    const messRec = String(message);
    
    chat.innerHTML += `<div class="bubble right" style="word-break: break-word">${messRec}</div>`;
    jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
}

// Main function for handling new messages
function handleOtherMessage(user) {
    // Use a selector to check if there's a div with data-username matching the user
    let existingMessage = document.querySelector(`.unreadMessages[data-username="${user}"]`);

    // Check if the user's unread message div already exists
    if (!existingMessage) {
        // Create a new unread message div for the specific user
        const unreadMessage = document.createElement('div');
        unreadMessage.classList.add('unreadMessages');
        unreadMessage.setAttribute('value', '1'); // Set initial value to 1
        unreadMessage.setAttribute('data-username', user); // Set data-username for this user
        unreadMessage.textContent = `${user} 1`; // Display initial unread count

        // Append to the messages content
        document.getElementById("messagesContent").appendChild(unreadMessage);
    } else {
        // If the element exists, update its value
        let currentValue = parseInt(existingMessage.getAttribute('value'), 10) || 0; // Default to 0 if NaN
        currentValue++; // Increment the value

        // Set the new value and update displayed text
        existingMessage.setAttribute('value', currentValue);
        existingMessage.textContent = `${user} ${currentValue}`;
    }

    // Update the overall message counter
    let messageValue = parseInt(messCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
    messageValue++;
    console.log(messageValue);
    messCounter.setAttribute('value', messageValue);
    messCounter.textContent = messageValue;
}

// Attach the global click event listener to the parent container
const messagesContent = document.getElementById("messagesContent");
// messagesContent.addEventListener('mouseenter', () => {
//     document.querySelector('.dropdown-content').classList.remove('hide');
// });

// // Hide dropdown on mouse leave from messagesContent
// messagesContent.addEventListener('mouseleave', () => {
//     document.querySelector('.dropdown-content').classList.add('hide');
// });
messagesContent.addEventListener('click', (event) => {
    const unreadMessage = event.target.closest('.unreadMessages');
    // Check if the clicked element is an unread message
    document.querySelector('.dropdown-content').classList.add('hide');
    document.querySelector('.dropdown-content').addEventListener('transitionend', function(event) {
        // Check which property has finished transitioning
        document.querySelector('.dropdown-content').classList.remove('hide');
        unreadMessage.remove();
    });
   
    
    //let existingMessage = document.querySelector(`.unreadMessages[data-username="${user}"]`);
    
    // Check if the user's unread message div already exists
    
        // Create a new unread message div for the specific user
        
        

        // Append to the messages content
        //document.getElementById("messagesContent").appendChild(unreadMessage);
    
        // If the element exists, update its value
        const currentValue = parseInt(unreadMessage.getAttribute('value'), 10); // Default to 0 if NaN
        const updatedCounter = parseInt(messCounter.getAttribute('value'), 10) - currentValue; // Increment the value

        // Set the new value and update displayed text
        // existingMessage.setAttribute('value', currentValue);
        // existingMessage.textContent = `${user} ${currentValue}`;
    

    // Update the overall message counter
    // let messageValue = parseInt(messCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
    // messageValue++;
    // console.log(messageValue);
    messCounter.setAttribute('value', updatedCounter);
    messCounter.textContent = updatedCounter;
    if (unreadMessage) {
        // Log the data-username attribute
        // const username = unreadMessage.getAttribute('data-username');
        console.log('Clicked username:', unreadMessage.getAttribute('data-username'));

        // Emit the message request (assuming socket is defined)
        receiver = unreadMessage.getAttribute('data-username'); // Use the user directly

        socket.emit('sendMeMessages', username, receiver);
    }
});
const invitationContent = document.getElementById("invitationContent");

invitationContent.addEventListener('click', (event) => {
    // Check if the clicked element is an unread invitation
    const invitation = event.target.closest('.invitation');
    
    if (invitation) {
        // Log the data-username attribute
        console.log('Clicked username:', invitation.getAttribute('data-username'));
        
        // Prompt the user with the confirm modal
        customConfirm(invitation.getAttribute('data-username'))
            .then((response) => {
                if (response === 'yes') {
                    // Remove the clicked invitation from the DOM
                    invitation.remove();
                    
                    // Emit the invite decision through WebSocket or handle it here
                    
                    socket.emit('confirm invite', { decision: true, invitingName: invitation.getAttribute('data-username') });
                }
                else if (response === 'no') {
                    invitation.remove();
                    
                    // Emit the invite decision through WebSocket or handle it here
                    
                    socket.emit('confirm invite', { decision: false, invitingName: invitation.getAttribute('data-username') });
                }
            });
    }
});





    socket.on('send invitation', (data) => {
        console.log('Invitation data received:', data);
        

    // Check if the user's unread message div already exists
    
        // Create a new unread message div for the specific user
        const invitation = document.createElement('div');
        invitation.classList.add('invitation');
        
        invitation.setAttribute('data-username', data.from); // Set data-username for this user
        invitation.textContent = `${data.from}`; // Display initial unread count

        // Append to the messages content
        document.getElementById("invitationContent").appendChild(invitation);
        let invitaionValue = parseInt(invCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
        invitaionValue++;
        console.log(invitaionValue);
        invCounter.setAttribute('value', invitaionValue);
        invCounter.textContent = invitaionValue;
        document.getElementById("invitationContent").appendChild(invitation);
        
    });
    
const typingIndicator = document.getElementById('typingIndicator');
//const receivers = document.getElementById('rec'); // Receiver's input element
 // Global receiver variable

// receivers.addEventListener('input', () => {
//     receiver = receivers.value.trim(); // Update receiver when the input changes
// });
    const fileInput = document.getElementById('fileInput'); // Replace with your file input element's ID

fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];

    // Check if a file is selected
    if (!file) {
        console.error('No file selected!');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
        const imageData = event.target.result; // This will be the data URL

        // Emit the file data and file type
        socket.emit('uploadImage', {
            imageData: imageData.split(',')[1], // Get the base64 encoded part
            fileType: file.type // This should be something like 'image/png', 'image/jpeg', etc.
        });
    };
    
    // Read the file as a Data URL
    reader.readAsDataURL(file);
});



    // Listening for the new image event
// socket.on('newImage', function(data) {
//     // Create a Blob from the received image data
//     const blob = new Blob([data], { type: 'image/jpeg' }); // Set the correct MIME type
//     const imageUrl = URL.createObjectURL(blob);

//     // Create an image element and set its source
//     const img = document.createElement('img');
//     img.src = imageUrl;

//     // Optionally, you can style or set attributes for the image
//     img.style.maxWidth = '100%'; // Example styling
//     img.style.height = 'auto';

//     // Append the image to the desired container in your chat interface
//     document.getElementById("menu").appendChild(img);
// });


    let typingTimer;
    const typingDelay = 2000; // 2 seconds typing delay
    const currentUsername = localStorage.getItem('username'); // Get the current user's username
    document.getElementById("initials").textContent = currentUsername.charAt(0).toUpperCase();
    const messageInput = document.getElementById('message');
    messageInput.addEventListener('input', () => {
        console.log("type");
        console.log(receiver)
        // Ensure receiver is set before emitting typing event
        if (receiver) {
            console.log("type");
            socket.emit('typing', true, receiver); // Pass the receiver to the typing event
        }

        // Clear the previous timer
    clearTimeout(typingTimer);

    // Set a new timer to emit typing stopped after the delay
    typingTimer = setTimeout(() => {
        if (receiver) {
            console.log("type");
            socket.emit('typing', false, receiver); // Emit typing stopped with receiver
        }
    }, typingDelay);
});

// Listen for 'userTyping' event from the server
socket.on('userTyping', ({ isTyping, sender }) => {
    const mails = document.getElementsByClassName("icon-keyboard");
    console.log(isTyping, sender);
    
    // Check if there is at least one element with the class "icon-keyboard"
    if (mails.length > 0) {
        const mail = mails[0]; // Get the first element

        if (isTyping && sender === receiver) {
            console.log("typing show");

            // Remove 'hidden' and add 'visible'
            mail.classList.remove('hidden');
            mail.classList.add('visible');
            
            mail.classList.add('blink');  // Add blink effect
        } else {
            console.log("typing hide");

            // Remove 'visible' and add 'hidden'
            mail.classList.remove('visible');
            mail.classList.add('hidden');

            mail.classList.remove('blink');  // Remove blink effect
        }
    }
});



function adjustMarginForScrollbar() {
    //const chat = document.getElementById('chat');
    const messages = document.querySelectorAll('.left');

    // Check if the scrollbar is visible
    const hasScrollbar = chat.scrollHeight > chat.clientHeight;

    // Adjust right margin of messages based on scrollbar presence
    messages.forEach(message => {
        if (hasScrollbar) {
            console.log("marg")
            message.style.marginRight = '10px'; // Adjust margin when scrollbar is present
        } 
    });
}



socket.on('messagesResponse', (decryptedMessages) => {
    console.log(decryptedMessages);
    //const chat = document.getElementById("chat");
    

            // Emit findUsers without awaiting the response
            

            // Assume that the server will respond with found users
            
                
                
                    
                    receiverElement.textContent = receiver;
                    // Clear existing content in #receiverAvatar
                    receiverAvatar.innerHTML = ''; 
                    
                    if (decryptedMessages.profileImage) {
                    // Check for the presence of an img element
                        const img = document.createElement('img');
                        img.id = 'receiverAvatar';
                        img.src = decryptedMessages.profileImage;
                        receiverAvatar.appendChild(img);
                    
                    }
                    else {
                        const initials = document.createElement('div');
                        initials.id = 'receiverInitials';
                        initials.textContent = receiver.charAt(0).toUpperCase();
                        receiverAvatar.appendChild(initials);
                    }
                    // Create initials element but keep it hidden initially
                    
                    
                    // Keep hidden initially
                    

                    // Append the image or initials based on availability
                    

                    
                
        
    chat.innerHTML = '';
    decryptedMessages.messages.forEach(message => {
        if (message.senderUsername == username) {
            chat.innerHTML += (`<div class="bubble left" style="word-break: break-word">${message.message}</div>`);
            adjustMarginForScrollbar();
            jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
        }
        else {
            chat.innerHTML += (`<div class="bubble right" style="word-break: break-word">${message.message}</div>`);
            jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
        }

    });
})
function closeModal() {
    const modal = document.getElementById('confirmModal');
    modal.classList.remove('show'); // Trigger shrink
    // modal.style.opacity = '0'; // Fade out
    // setTimeout(() => {
    //     modal.style.visibility = 'hidden'; // Hide after shrink animation
    //     modal.style.transform = 'translate(-50%, -50%) scale(0)'; // Reset transform
    // }, 300); // Delay matches the CSS transition duration
}

function customConfirm(inviting) {
    return new Promise((resolve) => {
        // Set the message
        document.getElementById('confirmText').textContent = `${inviting} has sent you a friend request. Do you accept?`;

        // Show the modal
        const modal = document.getElementById('confirmModal');
        modal.style.visibility = 'visible'; // Make it visible immediately
        

        // Trigger the animation
        setTimeout(() => {
            // modal.style.opacity = '1'; // Fade in
            // modal.style.transform = 'translate(-50%, -50%) scale(1)'; // Grow modal
            // modal.classList.add('show'); // Add class to trigger grow animation
            modal.classList.add('show');
        }, 10); // Slight delay to ensure the transition is applied

         // Short delay to ensure transition is applied

        // Yes button event
        document.getElementById('yesBtn').onclick = function() {
            resolve('yes');
            updateInvitationCounter();
            closeModal();
        };

        // No button event
        document.getElementById('noBtn').onclick = function() {
            resolve('no');
            updateInvitationCounter();
            closeModal();
        };

        // Cancel button event
        document.getElementById('cancelBtn').onclick = function() {
            resolve('cancel');
            closeModal();
        };

        // Function to update the invitation counter
        function updateInvitationCounter() {
            let invitaionValue = parseInt(document.getElementById('invCounter').getAttribute('value'), 10) || 0;
            invitaionValue--;
            document.getElementById('invCounter').setAttribute('value', invitaionValue);
            document.getElementById('invCounter').textContent = invitaionValue;
        }
    });
}

// Example usage
// document.getElementById('showConfirm').onclick = async function() {
//     const data = { from: 'John' }; // Example data
//     const result = await customConfirm(`${data.from} wants to be your friend. Do you accept?`);

//     if (result === 'yes') {
//         console.log("User accepted the friend request.");
//     } else if (result === 'no') {
//         console.log("User declined the friend request.");
//     } else {
//         console.log("User canceled the action.");
//     }
// };
// document.querySelector('.dropdownToggle').addEventListener('click', function() {
//     const dropdownContent = this.nextElementSibling; // Get the next sibling (.dropdown-content)
    
//     if (dropdownContent.classList.contains('hide')) {
//         dropdownContent.classList.remove('hide'); // Show the content
//     } else {
//         dropdownContent.classList.add('hide'); // Hide the content
//         document.querySelector('.dropdown-content').addEventListener('transitionend', function(event) {
//             // Check which property has finished transitioning
//             document.querySelector('.dropdown-content').classList.remove('hide');
            
//         });
        
//     }
// });

});
