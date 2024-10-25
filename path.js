const extension = avatar?.fileType?.split('/')[1];
    const validExtensions = ['jpeg', 'jpg', 'png', 'gif', 'bmp', 'svg', 'webp'];

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
                isCreatingGroup = false; // Reset the flag
                return;
            }
            console.log('Image saved successfully:', filePath);
            relativePath = `/uploads/${uniqueFileName}`;
            proceedToCreateGroup(invited, username, groupName, relativePath); // Ensure username is passed here
        });
    } else {
        // If no avatar, proceed with a null value
        console.log('No valid avatar provided. Proceeding without an avatar.');
        proceedToCreateGroup(invited, username, groupName, null);
    }