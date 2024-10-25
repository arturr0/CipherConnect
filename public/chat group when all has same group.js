const socket = io.connect('http://localhost:3000');
const baseUrl = window.location.origin;
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const findUsers = document.getElementById('findUsers');
    const receiverAvatar = document.getElementById('receiverAvatar');
    const chat = document.getElementById('message-container');
    const invCounter = document.getElementById('invCounter');
    const messCounter = document.getElementById('messCounter');
    const groupCounter = document.getElementById('groupCounter');
    const menuMessages = document.getElementById('messagesContent');
    const menuInvitation = document.getElementById('invitationContent');
    const menuGroups = document.getElementById('groupsContent');
    const unreadMessages = document.createElement('div');
    const receiverElement = document.getElementById('receiverName');
    const friendsContainer = document.getElementById('friendsContainer');
    const groupsContainer = document.getElementById('groupsContainer');
    const createGroupBtn = document.getElementById('sendGroup');
    let messageValue = 0;
    let receiver = '';
    let groupName = '';
    let group = null;
    let storeMessage = true;
    let avatar = null;
    const cryptoDiv = document.getElementById("crypto");
    const originalWidth = cryptoDiv.offsetWidth;
    const dropdownContainer = document.querySelectorAll('.dropdown-content');
    document.getElementById("group").addEventListener('click', () => {
        socket.emit('give me friends to group', username);
        const modal = document.getElementById('createGroup');
        modal.style.visibility = 'visible'; // Make it visible immediately
        menuGroups.classList.remove('dropdown-content');
        menuGroups.classList.remove('dropdown');
        menuInvitation.classList.remove('dropdown-content');
        menuInvitation.classList.remove('dropdown');
        menuMessages.classList.remove('dropdown-content');
        menuMessages.classList.remove('dropdown');

        // Trigger the animation
        setTimeout(() => {
            // modal.style.opacity = '1'; // Fade in
            // modal.style.transform = 'translate(-50%, -50%) scale(1)'; // Grow modal
            // modal.classList.add('show'); // Add class to trigger grow animation
            modal.classList.add('show');
        }, 10); // Slight delay to ensure the transition is applied

    });
    
    document.getElementById("cancelGroup").addEventListener('click', () => {
        createGroupBtn.style.opacity = '0.5';
        createGroupBtn.style.display = 'none';
        createGroupBtn.disabled = true;
        document.getElementById("createGroup").classList.remove("show");
        avatar = null;
        menuGroups.classList.add('dropdown-content');
        menuGroups.classList.add('dropdown');
        menuInvitation.classList.add('dropdown-content');
        menuInvitation.classList.add('dropdown');
        menuMessages.classList.add('dropdown-content');
        menuMessages.classList.add('dropdown');

    });
    document.getElementById("crypto").addEventListener('click', () => {
        storeMessage = !storeMessage;
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
                if (messageSent !== null && messageSent.trim() !== '' && ((receiver == '' && group != null) || (receiver != '' && group == null))) {
                    //const chat = document.getElementById("chat");
                    //const receiver = 'art2';
                    console.log("my mess");
                    const sendTime = new Date().toISOString();;
                    console.log(sendTime);
                    const hours = new Date().getHours();
                    const minutes = new Date().getMinutes();
                    
                    const sendDiv = document.createElement('div');
                    sendDiv.classList.add('bubble', 'left');
                    sendDiv.style.wordBreak = 'break-word';
                    sendDiv.textContent = inputValString;  // Add the message text
                    const timeAndIcon = document.createElement('div');
                    timeAndIcon.classList.add('timeAndIcon');
                    timeAndIcon.style.display = 'flex';
                    timeAndIcon.style.marginLeft = 'auto';
                    // Create a paragraph element for the date
                    const dateParagraph = document.createElement('p');
                    dateParagraph.textContent = `${hours < 10 ? '0' : ''}${hours}:${minutes < 10 ? '0' : ''}${minutes}`;  // Format and add the date
                    dateParagraph.style.marginBottom = '0';
                    
                    dateParagraph.style.textAlign = 'right';
                    
                    // Append the date paragraph to the message div
                    if(!storeMessage) {
                        const cryptoIcon = document.createElement('i');
                        cryptoIcon.classList.add('icon-user-secret');
                        cryptoIcon.style.marginRight = '3px';
                        cryptoIcon.style.marginTop = 'auto';
                        timeAndIcon.appendChild(cryptoIcon);    
                    }
                    timeAndIcon.appendChild(dateParagraph);
                    sendDiv.appendChild(timeAndIcon);
                    chat.appendChild(sendDiv);
                    adjustMarginForScrollbar();
                    
                    console.log(username);
                    
                    if (receiver != '') socket.emit('chatMessage', { username, messageSent, receiver, sendTime, storeMessage });
                    else if (group != null)
                        socket.emit('group message', { username, group, messageSent, storeMessage, sendTime })
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
    
    socket.on('send group message', (data) => {
        
        console.log(data);
        if (group == data.groupOfMessage) {
            adjustMarginForScrollbar();

    // Create a div element for the message bubble
            const recDiv = document.createElement('div');
            recDiv.classList.add('bubble', 'right');
            recDiv.style.wordBreak = 'break-word';
            recDiv.textContent = '';

// Create and add sender text
            const senderText = document.createElement('span');
            senderText.textContent = `${data.sender}:`;
            recDiv.appendChild(senderText);

            // Add line break
            recDiv.appendChild(document.createElement('br'));

            // Create and add message text
            const messageText = document.createElement('span');
            messageText.textContent = data.message;
            recDiv.appendChild(messageText);
            const timeAndIcon = document.createElement('div');
            timeAndIcon.classList.add('timeAndIcon');
            timeAndIcon.style.display = 'flex';
            timeAndIcon.style.marginRight = 'auto';
            // Create a paragraph element for the date
            const dateParagraph = document.createElement('p');
            dateParagraph.textContent = formatDateComparison(data.time);  // Format and add the date
            dateParagraph.style.marginBottom = '0';
            // Append the date paragraph to the message div
            timeAndIcon.appendChild(dateParagraph);
            if (!data.store) {
                const cryptoIcon = document.createElement('i');
                cryptoIcon.classList.add('icon-user-secret');
                
                cryptoIcon.style.marginTop = 'auto';
                cryptoIcon.style.marginLeft = '3px';
                timeAndIcon.appendChild(cryptoIcon);    
            }
            
    
            recDiv.appendChild(timeAndIcon);

            // Append the message div to the chat container
            chat.appendChild(recDiv);

            // Scroll to the bottom of the chat
            jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);    
        }
    });
    socket.on('disconnectedUserGroups', (data) => {
        
        console.log(data);
        const groupIds = data.map(groupData => groupData.groupId);

    // Select all SVG elements
    const svgElements = document.querySelectorAll('svg');

    // Loop through each SVG element
    svgElements.forEach(svg => {
        // Convert the 'group' attribute to a number for comparison
        const groupId = parseInt(svg.getAttribute('group'), 10);

        // Check if the groupId from the SVG matches any ID in the extracted groupIds array
        if (groupIds.includes(groupId)) {
            // Find the <circle> element inside this <svg>
            const circle = svg.querySelector('circle');

            // Change the fill color of the circle
            if (circle) {
                circle.setAttribute('fill', 'red');
            }
        }
    });
    });
    
    socket.on('group update', (data) => {
        
        console.log(data);
    });
    socket.on('invitationConfirmed', (data) => {
        console.log(data);
    });
    
    socket.on('userJoinedGroup', (data) => {
        console.log(data);
        const svgElements = document.querySelectorAll('svg');

    // Loop through each SVG element
        svgElements.forEach(svg => {
            // Check if the 'group' attribute matches the provided groupId
            if (svg.getAttribute('group') === data.groupId.toString()) {
                // Find the <circle> element inside this <svg>
                const circle = svg.querySelector('circle');
                
                // Change the fill color of the circle
                if (circle) {
                    circle.setAttribute('fill', 'green');
                }
            }
        });
    });
    socket.on('group confirmed', (data) => {
        console.log(data);
        let children = document.querySelectorAll('.user');  // Select all children

// Check if any child's 'data-id' attribute is NOT equal to the target value
        let groupExists = Array.from(children).some(child => 
            parseInt(child.getAttribute('groupid'), 10) == data.groupId
        );
        if (!groupExists) {
        const fragment = document.createDocumentFragment();
    
        // Loop over the found users
        
            const userDiv = document.createElement('div');
            userDiv.classList.add('user');
            userDiv.setAttribute('groupid', data.groupId);
            const profileContainer = document.createElement('div');
            profileContainer.classList.add('profile-container');
    
            // Create initials element but keep it hidden initially
            const initials = document.createElement('div');
            initials.classList.add('initials');
            initials.textContent = data.groupName.charAt(0).toUpperCase();
            initials.style.visibility = 'hidden';  // Keep hidden initially
            profileContainer.appendChild(initials);
    
            userDiv.appendChild(profileContainer);
    
            const userInfoDiv = document.createElement('div');
            userInfoDiv.classList.add('user-info');
            userInfoDiv.style.width = '100px';
            const usernameText = document.createElement('div');
            usernameText.classList.add('username');
            usernameText.textContent = data.groupName;
            userInfoDiv.appendChild(usernameText);
    
            
            const buttonsDiv = document.createElement('div');
            buttonsDiv.classList.add('buttons');
            // Create send message button
            const svgNS = "http://www.w3.org/2000/svg";

    // Create the <svg> element
            const svgElement = document.createElementNS(svgNS, "svg");
            svgElement.setAttribute("width", "20");
            svgElement.setAttribute("height", "20");
            svgElement.setAttribute("group", data.groupId);

            // Create the <circle> element
            const circle = document.createElementNS(svgNS, "circle");
            circle.setAttribute("cx", "10");
            circle.setAttribute("cy", "10");
            circle.setAttribute("r", "10");
            if (data.lineStatus == 1) circle.setAttribute("fill", "green");
            else circle.setAttribute("fill", "red");
            // Append the circle to the SVG
            svgElement.appendChild(circle);

            // Append the SVG to the parent container (e.g., div#svgContainer)
            buttonsDiv.appendChild(svgElement);
            const sendButton = document.createElement('button');
            sendButton.classList.add('send');
            sendButton.classList.add('toGroup');
            //sendButton.value = data.groupId;
            sendButton.dataset.groupId = data.groupId;
            sendButton.dataset.groupName = data.groupName;
            const sendIcon = document.createElement('i');
            sendIcon.classList.add('icon-comment');
            sendButton.appendChild(sendIcon);
            buttonsDiv.appendChild(sendButton);
    
            // Create block button
            const blockButton = document.createElement('button');
            blockButton.classList.add('block');
            blockButton.classList.add('quitGroup');
            blockButton.value = data.groupId;
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
                groupName = sendButton.dataset.groupName;
                group = sendButton.dataset.groupId;
                receiver = '';
                // Emit findUsers without awaiting the response
                //socket.emit('findUsers', searchUser); // This might be adjusted based on your logic
                
                socket.emit('group selected', username, group);
                // Assume that the server will respond with found users
                
                    
                    
                        receiverElement.textContent = groupName;
    
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
    
                        //socket.emit('sendMeMessages', username, receiver);
                    
                
            });
            
            
                // Select all elements with the class 'send'
    const sendButtons = document.querySelectorAll('.send');
    
                
                blockButton.addEventListener('click', () => {
                    blockButton.disabled = true;
                    console.log("click");
                    const blockedUser = blockButton.value;
                    if (group == blockedUser) {
                        group = null;
                        receiver = '';
                        receiverAvatar.innerHTML = '';
                        receiverElement.textContent = '';
                        chat.innerHTML = '';
                    }
                    // socket.emit('block', blockedUser, (response) => {
                    //     if (response.success) {
                    //         socket.emit('findUsers', searchUser);
                    //         console.log(response.message);
                    //     } else {
                    //         console.error('Failed to block user:', response.error);
                    //     }
                    // });
                });
                
            
    if (data.groupAvatar) {
    loadImageAsync(data.groupAvatar)
        .then((userImage) => {
            console.log('Image loaded:', userImage);

            //userImage.alt = `${friend.name}'s profile image`;
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

        
    
        groupsContainer.appendChild(fragment);
}
    });
    socket.on('groupInvites', (data) => {
        console.log(data);
        data.forEach(invite => {
            const invitation = document.createElement('div');
            invitation.classList.add('invitation');
            
            invitation.setAttribute('groupID', invite.groupId);
            invitation.setAttribute('groupName', invite.groupName);
            invitation.setAttribute('creator', invite.invitingUsername);
            invitation.textContent = `${invite.invitingUsername}`; // Display initial unread count

            // Append to the messages content
            document.getElementById("groupsContent").appendChild(invitation);
            let invitationValue = parseInt(groupCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
            invitationValue++;
            console.log(invitationValue);
            groupCounter.setAttribute('value', invitationValue);
            groupCounter.textContent = invitationValue;
            document.getElementById("groupsContent").appendChild(invitation);
        })
    });
    socket.on('groupInvite', (data) => {
        console.log(data);
        const invitation = document.createElement('div');
        invitation.classList.add('invitation');
        
        invitation.setAttribute('groupID', data.groupId);
        invitation.setAttribute('groupName', data.groupName);
        invitation.setAttribute('creator', data.creator); // Set data-username for this user
        invitation.textContent = `${data.creator}`; // Display initial unread count

        // Append to the messages content
        document.getElementById("groupsContent").appendChild(invitation);
        let invitationValue = parseInt(groupCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
        invitationValue++;
        console.log(invitationValue);
        groupCounter.setAttribute('value', invitationValue);
        groupCounter.textContent = invitationValue;
        document.getElementById("groupsContent").appendChild(invitation);
    });
    // Assuming socket is already initialized
 // Declare avatar variable at the top
 function setEqualUserDivWidth() {
    const userDivs = document.querySelectorAll('.username');
    let maxWidth = 0;

    // Find the maximum width of all user-info divs
    userDivs.forEach(userInfoDiv => {
        const width = userInfoDiv.offsetWidth;
        if (width > maxWidth) {
            maxWidth = width;
        }
    });

    // Apply the maximum width to all user-info divs
    userDivs.forEach(userInfoDiv => {
        userInfoDiv.style.width = `${maxWidth}px`;
    });
}

// After appending all the user divs, call this function to equalize their width


// Named function for the socket event
const handleFriendsToGroup = (data) => {
    let invited = []; // Initialize invited array on each call
    console.log(data);
    const groupName = "name"; // Modify this to get the actual group name if necessary
    const modalContent = document.getElementById('friendsToGroup');
    modalContent.innerHTML = ''; // Clear previous content
    const friends = document.createElement('div');
    friends.id = "scrolledFriends";
    modalContent.appendChild(friends);
    if (data.length > 0) {
    // Create the .accountContentText div
        createGroupBtn.style.display = 'block';
        document.getElementById('groupMessage').textContent = 'Create New Group'
        const accountContentText = document.createElement('div');
        
        accountContentText.classList.add('accountContentText');
        const nameInput = document.createElement('input');

// Set its attributes
        nameInput.type = 'text';
        nameInput.id = 'groupName';
        nameInput.placeholder = 'Enter Group Name';
        nameInput.style.height = '25px';
        modalContent.appendChild(nameInput);
        // Create the label and input (hidden)
        const label = document.createElement('label');
        label.setAttribute('for', 'groupAvatar');
        label.classList.add('custom-file-label');
        label.style.color = 'inherit';
        label.style.cursor = 'pointer';
        label.style.display = 'flex';
        label.style.justifyContent = 'space-between';
        label.style.alignItems = 'center';
        label.style.width = '100%';

        const span = document.createElement('span');
        span.textContent = 'Upload Avatar';
        span.style.fontSize = '20px';
        const iconContainer = document.createElement('div');
        iconContainer.classList.add('icon-upload-1', 'accIon');
        label.appendChild(span);
        label.appendChild(iconContainer);

        const input = document.createElement('input');
        input.type = 'file';
        input.id = 'groupAvatar';
        input.accept = 'image/*';
        input.style.display = 'none';

        accountContentText.appendChild(label);
        accountContentText.appendChild(input);
        modalContent.appendChild(accountContentText);

        const fragment = document.createDocumentFragment();

        // Create user divs for each friend
        data.forEach((friend) => {
            const userDiv = document.createElement('div');
            //const friends = document.getElementById('friends')
            userDiv.classList.add('user');
            userDiv.style.flexGrow = '1';
            const profileContainer = document.createElement('div');
            profileContainer.classList.add('profile-container');

            const initials = document.createElement('div');
            initials.classList.add('initials');
            initials.textContent = friend.name.charAt(0).toUpperCase();
            initials.style.visibility = 'hidden'; // Hide initials initially
            profileContainer.appendChild(initials);

            userDiv.appendChild(profileContainer);

            const userInfoDiv = document.createElement('div');
            userInfoDiv.classList.add('user-info');
            // userInfoDiv.style.minWidth = '100px';
            const usernameText = document.createElement('div');
            usernameText.classList.add('username');
            usernameText.style.flex = '1';
            usernameText.style.minWidth = '0';
            usernameText.textContent = friend.name;
            userInfoDiv.appendChild(usernameText);

            const checkbox = document.createElement('input'); // Create the checkbox
            checkbox.setAttribute('type', 'checkbox');
            checkbox.className = 'checkbox';

            userDiv.appendChild(userInfoDiv);
            userDiv.appendChild(checkbox);
            friends.appendChild(userDiv)
            fragment.appendChild(friends);

            // Load friend image if available
            if (friend.image) {
                loadImageAsync(friend.image)
                    .then((userImage) => {
                        userImage.alt = `${friend.name}'s profile image`;
                        userImage.classList.add('profile-image');
                        initials.style.display = 'none';

                        if (!profileContainer.querySelector('img.profile-image')) {
                            profileContainer.appendChild(userImage);
                        }
                    })
                    .catch((error) => {
                        initials.style.visibility = 'visible';
                    });
            } else {
                initials.style.visibility = 'visible';  
            }
            
        });
        
        
        modalContent.appendChild(fragment);

        // Manage invited users and checkboxes
        const checkboxes = document.querySelectorAll('.checkbox');

        // Clear previous event listeners (if any) and set up new listeners
        checkboxes.forEach((checkbox) => {
            checkbox.removeEventListener('change', checkbox.changeListener); // Clear previous listeners

            const changeListener = function () {
                const textContent = this.previousElementSibling.textContent;

                if (this.checked) {
                    invited.push(textContent);
                    checkConditions() // Add to invited
                } else {
                    invited = invited.filter(item => item !== textContent);
                    checkConditions() // Remove from invited
                }
                console.log(invited);
            };

            checkbox.changeListener = changeListener; // Save the listener function
            checkbox.addEventListener('change', changeListener);
        });

        // File input listener
        input.addEventListener('change', () => {
            const file = input.files[0];

            if (!file) {
                console.error('No file selected!');
                avatar = null; // Reset avatar if no file is selected
                return;
            }

            const reader = new FileReader();
            reader.onload = function (event) {
                avatar = {
                    imageData: event.target.result.split(',')[1], // Get the base64 encoded part
                    fileType: file.type // Image type
                };
                console.log('Avatar updated', avatar); // Ensure avatar is updated correctly
            };

            reader.readAsDataURL(file);
        });

        // Ensure the click handler for sending the group is only added once
        const sendGroupButton = document.getElementById("sendGroup");
        sendGroupButton.removeEventListener('click', sendGroupButton.clickListener); // Clear previous listeners
        const clickListener = () => {
            if (!avatar) {
                avatar = null; // Explicitly set avatar to null if no avatar uploaded
            }
            console.log(invited);
            socket.emit('createGroup', { groupName, invited, username, avatar });
            //menuGroups.classList.add('dropdown-content');
    
            // Reset avatar after group creation
            avatar = null;
        };

        sendGroupButton.clickListener = clickListener; // Save the listener function
        sendGroupButton.addEventListener('click', clickListener);
        function checkConditions() {
            const inputValue = nameInput.value.trim(); // Trim spaces
    
            // Check if input is not empty and array length is greater than 0
            if (inputValue.length > 0 && invited.length > 0) {
                createGroupBtn.style.opacity = '1';
                createGroupBtn.disabled = false;
 
                console.log("block");
            } else {
                createGroupBtn.style.opacity = '0.5';
                createGroupBtn.disabled = true; // Hide the button
                console.log("none");
            }
        }
    
        // Event listener for typing in input
        nameInput.addEventListener('input', checkConditions);
        setEqualUserDivWidth();
    }
    else document.getElementById('groupMessage').textContent = 'You don’t have any friends added yet. Add some friends first to create a group';
};


socket.on('groupCreated', ({ groupId, groupName }) => {
    console.log("created");

    // Update the group message and hide the 'createGroup' element
    
    const createGroupElement = document.getElementById('createGroup');
    createGroupElement.classList.remove('show');
    document.getElementById('friendsToGroup').innerHTML = '';

    // Add the transitionend listener to execute actions after the transition ends
    const handleTransitionEnd = (event) => {
        
            console.log('Transition completed');
            document.getElementById('groupMessage').textContent = 'Group successfully created!';
            // Perform actions after the transition ends
            createGroupElement.classList.add('show');

            // Remove the event listener after it's been triggered to avoid duplicate executions
            createGroupElement.removeEventListener('transitionend', handleTransitionEnd);
        
    };

    // Add the transitionend event listener
    createGroupElement.addEventListener("transitionend", handleTransitionEnd);

    // Reset the 'friendsToGroup' content
    

    // Update the button styles and disable it
    const createGroupBtn = document.getElementById('sendGroup');
    createGroupBtn.style.display = 'none';
    createGroupBtn.style.opacity = '0.5';
    createGroupBtn.disabled = true;
});

// Ensure the event handler is only registered once
socket.off('friendsToGroup'); // Remove any existing listeners for this event
socket.on('friendsToGroup', handleFriendsToGroup);



// Function to load image asynchronously
function loadImageAsync(imageUrl) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.src = imageUrl;
        img.onload = () => resolve(img);
        img.onerror = (error) => reject(error);
    });
}


    
    socket.on('pendingInvitations', (pendingInvitations) => {
        let newMessageCntr = 0;
        pendingInvitations.forEach(newMessage => {
            const invitation = document.createElement('div');
            invitation.classList.add('invitation');
            
            invitation.setAttribute('data-username', newMessage.username); // Set data-username for this user
            invitation.textContent = `${newMessage.username}`; // Display initial unread count

            // Append to the messages content
            document.getElementById("invitationContent").appendChild(invitation);
            let invitationValue = parseInt(invCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
            invitationValue++;
            console.log(invitationValue);
            invCounter.setAttribute('value', invitationValue);
            invCounter.textContent = invitationValue;
            document.getElementById("invitationContent").appendChild(invitation);
              
        });
        
    
    });
    socket.on('friendsList', (data) => {
        console.log(data);
        // Clear previous user list
        friendsContainer.innerHTML = ''; // Clear the previous list
        // Array.from(friendsContainer.children).forEach(child => {
        //     if (child.classList.contains('friends')) {
        //         friendsContainer.removeChild(child);
        //     }
        // });
        // Show loading icon when starting to append users
        // loadingIcon.classList.remove('display');
        // loadingIcon.classList.add('animate-spin');
        //document.getElementById("users").appendChild(loadingIcon);
    
        const fragment = document.createDocumentFragment();
    
        // Loop over the found users
        data.forEach((friend) => {
            const userDiv = document.createElement('div');
            userDiv.classList.add('user');
            userDiv.classList.add('friends');
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
            userInfoDiv.style.width = '100px';
            const usernameText = document.createElement('div');
            usernameText.classList.add('username');
            usernameText.textContent = friend.name;
            userInfoDiv.appendChild(usernameText);
    
            
            const buttonsDiv = document.createElement('div');
            buttonsDiv.classList.add('buttons');
            // Create send message button
            const svgNS = "http://www.w3.org/2000/svg";

    // Create the <svg> element
            const svgElement = document.createElementNS(svgNS, "svg");
            svgElement.setAttribute("width", "20");
            svgElement.setAttribute("height", "20");

            // Create the <circle> element
            const circle = document.createElementNS(svgNS, "circle");
            circle.setAttribute("cx", "10");
            circle.setAttribute("cy", "10");
            circle.setAttribute("r", "10");
            if(friend.online == 1) circle.setAttribute("fill", "green");
            else circle.setAttribute("fill", "red");
            // Append the circle to the SVG
            svgElement.appendChild(circle);

            // Append the SVG to the parent container (e.g., div#svgContainer)
            buttonsDiv.appendChild(svgElement);
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
                group = null;
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
                    if (receiver == blockedUser) {
                        receiver = '';
                        receiverAvatar.innerHTML = '';
                        receiverElement.textContent = '';
                        chat.innerHTML = '';
                    }
                    socket.emit('block', blockedUser, (response) => {
                        if (response.success) {
                            socket.emit('findUsers', searchUser);
                            console.log(response.message);
                        } else {
                            console.error('Failed to block user:', response.error);
                        }
                    });
                });
                
            
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
        if (receiver == data) {
            receiver = '';
            receiverAvatar.innerHTML = '';
            receiverElement.textContent = '';
            chat.innerHTML = '';
        }
        socket.emit('findUsers', searchUser);
        socket.emit('give me friends to group', username);
    });
    socket.on('acceptedGroupInvites', (data) => {
        console.log(data);
        // Clear previous user list
        //friendsContainer.innerHTML = ''; // Clear the previous list
        
        // Show loading icon when starting to append users
        // loadingIcon.classList.remove('display');
        // loadingIcon.classList.add('animate-spin');
        //document.getElementById("users").appendChild(loadingIcon);
    
        const fragment = document.createDocumentFragment();
    
        // Loop over the found users
        data.forEach((Mygroup) => {
            const userDiv = document.createElement('div');
            userDiv.classList.add('user');
            
            const profileContainer = document.createElement('div');
            profileContainer.classList.add('profile-container');
    
            // Create initials element but keep it hidden initially
            const initials = document.createElement('div');
            initials.classList.add('initials');
            initials.textContent = Mygroup.groupName.charAt(0).toUpperCase();
            initials.style.visibility = 'hidden';  // Keep hidden initially
            profileContainer.appendChild(initials);
    
            userDiv.appendChild(profileContainer);
    
            const userInfoDiv = document.createElement('div');
            userInfoDiv.classList.add('user-info');
            userInfoDiv.style.width = '100px';
            const usernameText = document.createElement('div');
            usernameText.classList.add('username');
            usernameText.textContent = Mygroup.groupName;
            userInfoDiv.appendChild(usernameText);
    
            
            const buttonsDiv = document.createElement('div');
            buttonsDiv.classList.add('buttons');
            // Create send message button
            const svgNS = "http://www.w3.org/2000/svg";

    // Create the <svg> element
            const svgElement = document.createElementNS(svgNS, "svg");
            svgElement.setAttribute("width", "20");
            svgElement.setAttribute("height", "20");
            svgElement.setAttribute("group", Mygroup.groupId);
            // Create the <circle> element
            const circle = document.createElementNS(svgNS, "circle");
            circle.setAttribute("cx", "10");
            circle.setAttribute("cy", "10");
            circle.setAttribute("r", "10");
            if (Mygroup.online == 1) circle.setAttribute("fill", "green");
            else circle.setAttribute("fill", "red");
            // Append the circle to the SVG
            svgElement.appendChild(circle);

            // Append the SVG to the parent container (e.g., div#svgContainer)
            buttonsDiv.appendChild(svgElement);
            const sendButton = document.createElement('button');
            sendButton.classList.add('send');
            sendButton.dataset.groupId = Mygroup.groupId;
            sendButton.dataset.groupName = Mygroup.groupName;
            const sendIcon = document.createElement('i');
            sendIcon.classList.add('icon-comment');
            sendButton.appendChild(sendIcon);
            buttonsDiv.appendChild(sendButton);
    
            // Create block button
            const blockButton = document.createElement('button');
            blockButton.classList.add('block');
            blockButton.value = Mygroup.groupId;
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
                receiver = '';
                group = sendButton.dataset.groupId;
                groupName = sendButton.dataset.groupName;
                socket.emit('group selected', username, group);
                // Emit findUsers without awaiting the response
                //socket.emit('findUsers', searchUser); // This might be adjusted based on your logic
    
                // Assume that the server will respond with found users
                
                    
                    
                        receiverElement.textContent = groupName;
    
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
    
                        //socket.emit('sendMeMessages', username, receiver);
                    
                
            });
            
            
                // Select all elements with the class 'send'
    const sendButtons = document.querySelectorAll('.send');
    
                
                blockButton.addEventListener('click', () => {
                    blockButton.disabled = true;
                    console.log("click");
                    const blockedUser = blockButton.value;
                    if (group == blockedUser) {
                        //group = null;
                        receiverAvatar.innerHTML = '';
                        receiverElement.textContent = '';
                        chat.innerHTML = '';
                    }
                    // socket.emit('block', blockedUser, (response) => {
                    //     if (response.success) {
                    //         socket.emit('findUsers', searchUser);
                    //         console.log(response.message);
                    //     } else {
                    //         console.error('Failed to block user:', response.error);
                    //     }
                    // });
                });
                
            
    if (Mygroup.groupAvatar) {
    loadImageAsync(Mygroup.groupAvatar)
        .then((userImage) => {
            console.log('Image loaded:', userImage);

            //userImage.alt = `${friend.name}'s profile image`;
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
    
        groupsContainer.appendChild(fragment);
        
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
        userInfoDiv.style.width = '100px';
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
            group = null;
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
                if (receiver == blockedUser) {
                    receiver = '';
                    receiverAvatar.innerHTML = '';
                    receiverElement.textContent = '';
                    chat.innerHTML = '';
                }
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
        handleIncomingMessage(data);
    } else {
        handleOtherMessage(data.user);
    }
});

function handleIncomingMessage(message) {
    adjustMarginForScrollbar();

    // Create a div element for the message bubble
    const recDiv = document.createElement('div');
    recDiv.classList.add('bubble', 'right');
    recDiv.style.wordBreak = 'break-word';
    recDiv.textContent = message.message;  // Add the message text
    const timeAndIcon = document.createElement('div');
    timeAndIcon.classList.add('timeAndIcon');
    timeAndIcon.style.display = 'flex';
    timeAndIcon.style.marginRight = 'auto';
    // Create a paragraph element for the date
    const dateParagraph = document.createElement('p');
    dateParagraph.textContent = formatDateComparison(message.date);  // Format and add the date
    dateParagraph.style.marginBottom = '0';
    // Append the date paragraph to the message div
    timeAndIcon.appendChild(dateParagraph);
    if(!message.store) {
        const cryptoIcon = document.createElement('i');
        cryptoIcon.classList.add('icon-user-secret');
        
        cryptoIcon.style.marginTop = 'auto';
        cryptoIcon.style.marginLeft = '3px';
        timeAndIcon.appendChild(cryptoIcon);    
    }
    
    
    recDiv.appendChild(timeAndIcon);

    // Append the message div to the chat container
    chat.appendChild(recDiv);

    // Scroll to the bottom of the chat
    jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
}

function formatDateComparison(targetDate) {
    const now = new Date();
    targetDate = new Date(targetDate);  // Convert the string to a Date object

    // Extract day, month, and year from both dates
    const nowDay = now.getDate();
    const nowMonth = now.getMonth();
    const nowYear = now.getFullYear();
    
    const targetDay = targetDate.getDate();
    const targetMonth = targetDate.getMonth();
    const targetYear = targetDate.getFullYear();
    
    // Compare day, month, and year
    if (nowDay === targetDay && nowMonth === targetMonth && nowYear === targetYear) {
        // If same, return hours and minutes
        const hours = targetDate.getHours();
        const minutes = targetDate.getMinutes();
        return `${hours < 10 ? '0' : ''}${hours}:${minutes < 10 ? '0' : ''}${minutes}`; // Add leading zero to minutes if needed
    } else {
        // If different, return full date in "year-month-day" format
        return `${targetYear}.${(targetMonth + 1).toString().padStart(2, '0')}.${targetDay.toString().padStart(2, '0')}`;
    }
}


// Example usage
//const targetDate = new Date('2024-10-06T09:40:00'); // Replace with your target date
//console.log(formatDateComparison(targetDate));

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
// Define the common function to handle clicks
function confirmInvitation(contentType, event, emitType, cntr) {
    const element = event.target.closest('.invitation');
    
    if (element) {
        // Log the data-username or data-groupname attribute based on contentType
        const nameAttr = contentType === 'invitation' ? 'data-username' : 'groupID';
        const nameValue = element.getAttribute(nameAttr);
        console.log(`Clicked ${contentType}:`, nameValue);
        let gruopName = null;
        let groupInvitingName = null;
        if (contentType != 'invitation') {
            gruopName = element.getAttribute('groupName');
            groupInvitingName = element.getAttribute('creator');
        }
        // Prompt the user with the confirm modal
        customConfirm(nameValue, cntr, gruopName, groupInvitingName)
            .then((response) => {
                if (response === 'yes') {
                    // Remove the clicked element from the DOM
                    element.remove();
                    
                    // Emit the decision through WebSocket with custom event and data
                    socket.emit(emitType, { decision: true, invitingName: nameValue });
                } else if (response === 'no') {
                    element.remove();
                    
                    // Emit the decision through WebSocket with custom event and data
                    socket.emit(emitType, { decision: false, invitingName: nameValue });
                }
            });
    }
}

// Add event listeners with the custom function for invitations
invitationContent.addEventListener('click', (event) => {
    confirmInvitation('invitation', event, 'confirm invite', 'invCounter');
});

// Add event listeners with the custom function for groups
document.getElementById("groupsContent").addEventListener('click', (event) => {
    console.log("click");
    confirmInvitation('group', event, 'confirm group', 'groupCounter');
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
        let invitationValue = parseInt(invCounter.getAttribute('value'), 10) || 0; // Default to 0 if NaN
        invitationValue++;
        console.log(invitationValue);
        invCounter.setAttribute('value', invitationValue);
        invCounter.textContent = invitationValue;
        document.getElementById("invitationContent").appendChild(invitation);
        
    });
    
const typingIndicator = document.getElementById('typingIndicator');
//const receivers = document.getElementById('rec'); // Receiver's input element
 // Global receiver variable

// receivers.addEventListener('input', () => {
//     receiver = receivers.value.trim(); // Update receiver when the input changes
// });
    const userAvatar = document.getElementById('userAvatar'); // Replace with your file input element's ID

userAvatar.addEventListener('change', () => {
    const file = userAvatar.files[0];

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
            // chat.innerHTML += (`<div class="bubble left" style="word-break: break-word">${message.message}</div>`);
            // adjustMarginForScrollbar();
            // jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
            const sendDiv = document.createElement('div');
            sendDiv.classList.add('bubble', 'left');
            sendDiv.style.wordBreak = 'break-word';
            sendDiv.textContent = message.message;  // Add the message text
            const timeAndIcon = document.createElement('div');
            timeAndIcon.classList.add('timeAndIcon');
            timeAndIcon.style.display = 'flex';
            timeAndIcon.style.marginLeft = 'auto';
            // Create a paragraph element for the date
            const dateParagraph = document.createElement('p');
            dateParagraph.textContent = `${formatDateComparison(message.time)}`;
            dateParagraph.style.marginBottom = '0';
            dateParagraph.style.textAlign = 'right';
            if(message.toDelete == 1) {
                const cryptoIcon = document.createElement('i');
                cryptoIcon.classList.add('icon-user-secret');
                cryptoIcon.style.marginRight = '3px';
                cryptoIcon.style.marginTop = 'auto';
                timeAndIcon.appendChild(cryptoIcon);    
            }
            timeAndIcon.appendChild(dateParagraph);
            sendDiv.appendChild(timeAndIcon);
            // Append the date paragraph to the message div
            //sendDiv.appendChild(dateParagraph);
            chat.appendChild(sendDiv);
            
            
            
            
            adjustMarginForScrollbar();
            jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
        }
        else {
            // chat.innerHTML += (`<div class="bubble right" style="word-break: break-word">${message.message}</div>`);
            // jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
            adjustMarginForScrollbar();
            const timeAndIcon = document.createElement('div');
            timeAndIcon.classList.add('timeAndIcon');
            timeAndIcon.style.display = 'flex';
            timeAndIcon.style.marginRight = 'auto';
            // Create a div element for the message bubble
            const recDiv = document.createElement('div');
            recDiv.classList.add('bubble', 'right');
            recDiv.style.wordBreak = 'break-word';
            recDiv.textContent = message.message;  // Add the message text

            // Create a paragraph element for the date
            const dateParagraph = document.createElement('p');
            dateParagraph.textContent = formatDateComparison(message.time);  // Format and add the date
            dateParagraph.style.marginBottom = '0';
            // Append the date paragraph to the message div
            timeAndIcon.appendChild(dateParagraph);
            if(message.toDelete == 1) {
                const cryptoIcon = document.createElement('i');
                cryptoIcon.classList.add('icon-user-secret');
                
                cryptoIcon.style.marginTop = 'auto';
                cryptoIcon.style.marginLeft = '3px';
                timeAndIcon.appendChild(cryptoIcon);    
            }
    
    
            recDiv.appendChild(timeAndIcon);
            //recDiv.appendChild(dateParagraph);

            // Append the message div to the chat container
            chat.appendChild(recDiv);
            jQuery("#message-container").scrollTop(jQuery("#message-container")[0].scrollHeight);
        }

    });
})
function closeModal() {
    const modal = document.querySelector('.modal');
    modal.classList.remove('show'); // Trigger shrink
    menuGroups.classList.add('dropdown-content');
    menuGroups.classList.add('dropdown');
    menuInvitation.classList.add('dropdown-content');
    menuInvitation.classList.add('dropdown');
    menuMessages.classList.add('dropdown-content');
    menuMessages.classList.add('dropdown');
    // modal.style.opacity = '0'; // Fade out
    // setTimeout(() => {
    //     modal.style.visibility = 'hidden'; // Hide after shrink animation
    //     modal.style.transform = 'translate(-50%, -50%) scale(0)'; // Reset transform
    // }, 300); // Delay matches the CSS transition duration
}

function customConfirm(inviting, cntr, groupName, groupInvitingName) {
    return new Promise((resolve) => {
        // Set the message
        console.log(dropdownContainer)
        menuGroups.classList.remove('dropdown-content');
        menuGroups.classList.remove('dropdown');
        menuInvitation.classList.remove('dropdown-content');
        menuInvitation.classList.remove('dropdown');
        menuMessages.classList.remove('dropdown-content');
        menuMessages.classList.remove('dropdown');
        if (cntr == 'invCounter') document.getElementById('confirmText').textContent = `${inviting} has sent you a friend request. Do you accept?`;
        else document.getElementById('confirmText').textContent = `${groupInvitingName} has invited you to join the group ${groupName}. Do you accept?`;
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
            updateInvitationCounter(cntr);
            closeModal();
        };

        // No button event
        document.getElementById('noBtn').onclick = function() {
            resolve('no');
            updateInvitationCounter(cntr);
            closeModal();
        };

        // Cancel button event
        document.getElementById('cancelBtn').onclick = function() {
            resolve('cancel');
            closeModal();
        };

        // Function to update the invitation counter
        function updateInvitationCounter(cntr) {
            let invitationValue = parseInt(document.getElementById(cntr).getAttribute('value'), 10) || 0;
            invitationValue--;
            document.getElementById(cntr).setAttribute('value', invitationValue);
            document.getElementById(cntr).textContent = invitationValue;
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
