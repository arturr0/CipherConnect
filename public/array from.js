const modalContent = document.querySelector('#createGroup .modal-content');
const buttons = document.querySelector('.modalButtons');

// Remove all other children except the one you want to keep
Array.from(modalContent.children).forEach(child => {
    if (!child.classList.contains('modalButtons')) {
        modalContent.removeChild(child);
    }
});

const modalContent = document.querySelector('#createGroup .modal-content');
    const buttons = document.querySelector('.modalButtons');

    Array.from(modalContent.children).forEach(child => {
        if (child !== buttons) {
            modalContent.removeChild(child);
        }
    });