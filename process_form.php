<?php
// PHP Processing Logic - MUST be at the very top before any HTML output or whitespace

// Define your email address where you want to receive messages (for email sending - currently commented out)
$receiving_email_address = 'josephabankwah36@gmail.com'; // IMPORTANT: Change this to your actual email address

// Database credentials
$servername = "localhost"; // Usually 'localhost' for local servers
$username = "root";        // Default WAMP username
$password = "";            // Default WAMP password (empty)
$dbname = "portfolio_db";  // The database name you created (as per previous instructions)

// IMPORTANT: If you're using a web host, these credentials will be different.
// Your hosting provider will give you the correct DB_HOST, DB_USER, DB_PASSWORD, DB_NAME.
// Never use 'root' and an empty password in a production environment!

// Initialize status messages
$status_message = '';
$status_type = ''; // 'success', 'error', 'warning'

// Check if the form was submitted using POST method
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // 1. Sanitize and validate input
    // Using (string) cast for basic string sanitization as FILTER_SANITIZE_STRING is deprecated.
    // PDO prepared statements provide the primary sanitization for database insertion.
    $name = (string) ($_POST["name"] ?? '');
    $email = filter_var(trim($_POST["email"] ?? ''), FILTER_SANITIZE_EMAIL);
    $subject = (string) ($_POST["subject"] ?? '');
    $message = (string) ($_POST["message"] ?? '');

    // Basic server-side validation
    if (empty($name) || empty($email) || empty($subject) || empty($message)) {
        // Redirect back to this page with an error status
        header("Location: index.php?status=error&message=" . urlencode("Please fill in all fields."));
        exit();
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Redirect back to this page with an error status
        header("Location: index.php?status=error&message=" . urlencode("Invalid email format."));
        exit();
    }

    // --- Database Insertion ---
    $db_success = false;
    $conn = null; // Initialize connection variable

    try {
        // Create database connection using PDO
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Set PDO error mode

        // Prepare SQL statement to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO contacts (name, email, subject, message) VALUES (:name, :email, :subject, :message)");

        // Bind parameters
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':subject', $subject);
        $stmt->bindParam(':message', $message);

        // Execute the statement
        $stmt->execute();
        $db_success = true; // Flag for successful DB insertion

    } catch(PDOException $e) {
        // In a production environment, you'd log this error instead of displaying it
        error_log("Database Error: " . $e->getMessage());
    } finally {
        // Close connection
        if ($conn) {
            $conn = null;
        }
    }

    // --- Email Sending (OPTIONAL - CURRENTLY COMMENTED OUT TO AVOID ERRORS) ---
    // Uncomment and configure if you have a mail server or use a library like PHPMailer
    $email_sent = false;
    /*
    // Prepare email content
    $email_subject = "New Contact From Your Portfolio: " . $subject;
    $email_body = "You have received a new message from your website contact form.\n\n";
    $email_body .= "Name: " . $name . "\n";
    $email_body .= "Email: " . $email . "\n";
    $email_body .= "Subject: " . $subject . "\n";
    $email_body .= "Message:\n" . $message . "\n";

    // Set email headers
    $headers = "From: Your Portfolio <noreply@yourdomain.com>\r\n"; // IMPORTANT: Change 'yourdomain.com'
    $headers .= "Reply-To: " . $email . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/plain; charset=iso-8859-1\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    // Prevent header injection
    $headers = str_replace(array("\n", "\r", "%0a", "%0d"), '', $headers);

    // Send the email
    if (mail($receiving_email_address, $email_subject, $email_body, $headers)) {
        $email_sent = true;
    } else {
        error_log("Email sending failed for: " . $email); // Log failures
    }
    */


    // --- Final Redirect based on outcomes ---
    // Since email is commented out, the status messages will reflect DB outcome
    if ($db_success) {
        header("Location: index.php?status=success&message=" . urlencode("Your message has been saved successfully!"));
    } else {
        header("Location: index.php?status=error&message=" . urlencode("Oops! Your message could not be saved to the database."));
    }
    exit(); // Always exit after a header redirect
}

// Display status messages from URL parameters if present (after redirect)
if (isset($_GET['status']) && isset($_GET['message'])) {
    $status_type = htmlspecialchars($_GET['status']);
    $status_message = htmlspecialchars(urldecode($_GET['message']));
}
?>