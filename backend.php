<?php
session_start();
include 'db_connect.php'; // Connect to database

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    // Registration
    if (isset($_POST["register"])) {
        $name = $_POST["name"];
        $email = $_POST["email"];
        $password = password_hash($_POST["password"], PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $password);

        if ($stmt->execute()) {
            echo "Registration successful. You can now log in.";
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    }

    // Login
    if (isset($_POST["login"])) {
        $email = $_POST["email"];
        $password = $_POST["password"];

        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $hashed_password);
            $stmt->fetch();

            if (password_verify($password, $hashed_password)) {
                $_SESSION["user_id"] = $id;
                echo "Login successful. Redirecting...";
                header("refresh:2; url=dashboard.php"); // Redirect after login
                exit();
            } else {
                echo "Invalid password.";
            }
        } else {
            echo "No account found with that email.";
        }
        $stmt->close();
    }
}
$conn->close();
?>
