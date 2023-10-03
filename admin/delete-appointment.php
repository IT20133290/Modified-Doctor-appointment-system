<?php
session_start();

if (!isset($_SESSION["user"]) || $_SESSION["user"] === "" || $_SESSION['usertype'] !== 'a') {
    header("location: ../login.php");
    exit; // Terminate script execution after redirection
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET["id"])) {
    // Import database
    require_once("../connection.php");

    // Sanitize and validate input data (in this case, the "id" parameter)
    $id = filter_var($_GET["id"], FILTER_VALIDATE_INT);

    if ($id !== false) {
        // Use prepared statements to delete the appointment safely
        $stmt = $database->prepare("DELETE FROM appointment WHERE appoid = ?");
        $stmt->bind_param("i", $id);

        if ($stmt->execute()) {
            header("location: appointment.php");
            exit;
        } else {
            // Handle the database error gracefully
            $error = "Database error: " . $stmt->error;
        }
    } else {
        $error = "Invalid input data";
    }
}
