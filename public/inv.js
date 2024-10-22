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
                            groupId: groupId,
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
