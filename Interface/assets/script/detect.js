// Function to toggle the visibility of upload options
function showUploadOptions() {
    const uploadOptions = document.getElementById('uploadOptions');
    uploadOptions.classList.toggle('hidden');
}




// Function to submit the form and redirect to another page
function submitForm(event) {
    event.preventDefault();

    // Retrieve form data
    const duration = document.getElementById('duration').value;
    const protocol_type = document.getElementById('protocol_type').value;
    const service = document.getElementById('service').value;
    const SRC_Bytes = document.getElementById('SRC_Bytes').value;
    const DST_Bytes = document.getElementById('DST_Bytes').value;
    const Flags = document.getElementById('Flags').value;
    const Wrong_Fragments = document.getElementById('Wrong_Fragments').value;
    const Num_Failed_Logins = document.getElementById('Num_Failed_Logins').value;
    const Num_Access_Files = document.getElementById('Num_Access_Files').value;
    const Num_Compromised = document.getElementById('Num_Compromised').value;
    const Num_File_Creations = document.getElementById('Num_File_Creations').value;
    const Count = document.getElementById('Count').value;
    // Add similar lines for other fields

    // Create a JavaScript object with the form data
    const formData = {
        duration,
        protocol_type,
        service,
        SRC_Bytes,
        DST_Bytes,
        Flags,
        Wrong_Fragments,
        Num_Failed_Logins,
        Num_Access_Files,
        Num_Compromised,
        Num_File_Creations,
        Count

        


        // Add other fields similarly
    };

    function submitForm() {
        // Redirect to the result page
        window.location.href = 'result.html';
    }
}