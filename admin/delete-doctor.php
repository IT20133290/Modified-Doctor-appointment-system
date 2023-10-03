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
        // Use prepared statements to fetch the doctor's email
        $stmt = $database->prepare("SELECT docemail FROM doctor WHERE docid = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $stmt->bind_result($email);

        if ($stmt->fetch()) {
            $stmt->close();

            // Use prepared statements to delete the web user and doctor accounts safely
            $stmt = $database->prepare("DELETE FROM webuser WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();

            $stmt = $database->prepare("DELETE FROM doctor WHERE docemail = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();

            header("location: doctors.php");
            exit;
        } else {
            // Handle the case when the doctor with the specified ID is not found
            $error = "Doctor not found";
        }
    } else {
        $error = "Invalid input data";
    }
}
