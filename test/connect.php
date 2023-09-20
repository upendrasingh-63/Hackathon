<?php
// Function to sanitize and validate input
function sanitize_input($input) {
    // Remove leading and trailing whitespace
    $input = trim($input);
    // Prevent potential security issues (XSS attacks)
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    return $input;
}

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate and sanitize user inputs
    $firstName = sanitize_input($_POST['firstName']);
    $lastName = sanitize_input($_POST['lastName']);
    $gender = sanitize_input($_POST['gender']);
    $email = sanitize_input($_POST['email']);
    $password = $_POST['password']; // Not sanitized yet
    $number = sanitize_input($_POST['number']);

    // Hash the password using bcrypt
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'test');
    if ($conn->connect_error) {
        die("Connection Failed: " . $conn->connect_error);
    }

    // Prepare the SQL statement
    $stmt = $conn->prepare("INSERT INTO testtable (firstName, lastName, gender, email, password, number) VALUES (?, ?, ?, ?, ?, ?)");
    $sql = "SELECT * FROM `testtable`";
    $result = mysqli_query($conn, $sql);
    if (!$stmt) {
        die("Error in SQL statement preparation: " . $conn->error);
    }

    // Bind parameters
    $stmt->bind_param("ssssss", $firstName, $lastName, $gender, $email, $hashedPassword, $number);

    // Execute the statement
    $executed = $stmt->execute();
    if (!$executed) {
        die("Error in SQL statement execution: " . $stmt->error);
    }

    // Close resources
    $stmt->close();
    $conn->close();

    // Redirect to amazone.html after successful submission
    header('Location: amazone.html');
    exit(); // Make sure to exit to prevent further script execution
}
?>
