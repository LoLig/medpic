document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token'); // Assuming the URL is something like /reset-password.html?token=xxxx

    Swal.fire({
        title: 'Reset Password',
        html: `
            <input type="password" id="swal-input1" class="swal2-input" placeholder="New Password">
            <input type="password" id="swal-input2" class="swal2-input" placeholder="Confirm New Password">
        `,
        focusConfirm: false,
        preConfirm: () => {
            const newPassword = Swal.getPopup().querySelector('#swal-input1').value;
            const confirmPassword = Swal.getPopup().querySelector('#swal-input2').value;

            if (!newPassword || !confirmPassword) {
                Swal.showValidationMessage('Both fields are required');
                return false;
            }

            if (newPassword !== confirmPassword) {
                Swal.showValidationMessage('Passwords do not match');
                return false;
            }

            return { newPassword: newPassword, confirmPassword: confirmPassword }; // No need to return confirmPassword in practice, but showing structure here
        },
        showCancelButton: true,
        confirmButtonText: 'Submit',
    }).then((result) => {
        if (result.isConfirmed) {
            fetch('/api/users/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ token, newPassword: result.value.newPassword }),
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json(); // Parse JSON response
            })
            .then(data => {
                Swal.fire('Success!', 'Your password has been reset.', 'success')
                .then(() => {
                    window.location.href = '/index.html'; // Redirect to index.html or any other page
                });
            })
            .catch((error) => {
                console.error('Error:', error);
                Swal.fire('Error!', 'Failed to reset password. Please try again.', 'error');
            });
        }
    });
});
